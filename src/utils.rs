use std::{ffi::c_void, ptr::null_mut};

use ntapi::{
    ntpebteb::PEB,
    ntpsapi::PROCESS_BASIC_INFORMATION,
    ntrtl::{RtlCreateProcessParametersEx, RtlInitUnicodeString, RTL_USER_PROCESS_PARAMETERS},
    winapi::{
        shared::ntdef::{NT_SUCCESS, UNICODE_STRING},
        um::winnt::{ACCESS_MASK, IMAGE_NT_HEADERS32, LARGE_INTEGER},
    },
    FIELD_OFFSET,
};
use widestring::WideCString;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_INVALID_IMAGE_HASH, FARPROC, HANDLE,
        INVALID_HANDLE_VALUE, NTSTATUS,
    },
    Storage::FileSystem::{
        FlushFileBuffers, GetFileSizeEx, SetEndOfFile, SetFilePointerEx, WriteFile, FILE_BEGIN,
    },
    System::{
        Diagnostics::Debug::{
            WriteProcessMemory, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            CreateFileMappingW, MapViewOfFile, VirtualAllocEx, FILE_MAP_READ, MEM_COMMIT,
            MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE,
        },
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
        Threading::{NtQueryInformationProcess, ProcessBasicInformation},
        WindowsProgramming::OBJECT_ATTRIBUTES,
    },
};

pub type NtCreateSection = fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    MaximumSize: *mut LARGE_INTEGER,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: HANDLE,
) -> NTSTATUS;

pub type NtCreateProcessEx = fn(
    *mut HANDLE,
    u32,
    *mut OBJECT_ATTRIBUTES,
    HANDLE,
    u32,
    HANDLE,
    *mut c_void,
    *mut c_void,
    BOOL,
) -> i32;

pub type WritePtrAddrToMemory = fn(
    hprocess: HANDLE,
    lpbaseaddress: *const c_void,
    lpbuffer: *mut *mut c_void,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize,
) -> BOOL;

pub unsafe fn get_file_size(file_handle: HANDLE) -> Result<i64, u32> {
    let mut file_size: i64 = 0;
    if GetFileSizeEx(file_handle, &mut file_size) == 0 {
        let err = GetLastError();
        return Err(err);
    }

    return Ok(file_size);
}

pub unsafe fn write_file_flushed(
    target_handle: HANDLE,
    buffer: &[u8],
    length: u32,
) -> Result<u32, u32> {
    set_file_pointer(target_handle, 0, FILE_BEGIN)?;

    let mut bytes_written: u32 = 0;
    if WriteFile(
        target_handle,
        buffer.as_ptr(),
        length,
        &mut bytes_written,
        null_mut(),
    ) == 0
    {
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    {
        log::debug!("Bytes written to target: {}", bytes_written);
    }

    if FlushFileBuffers(target_handle) == 0 {
        return Err(GetLastError());
    }

    if SetEndOfFile(target_handle) == 0 {
        return Err(GetLastError());
    }

    Ok(bytes_written)
}

pub unsafe fn set_file_pointer(
    file_handle: HANDLE,
    distance_to_move: i64,
    move_method: u32,
) -> Result<(), u32> {
    if SetFilePointerEx(file_handle, distance_to_move, null_mut(), move_method) == 0 {
        let err = GetLastError();
        return Err(err);
    }
    return Ok(());
}

unsafe fn get_file_mapped_view_handle(file_handle: HANDLE) -> Result<HANDLE, u32> {
    // If this parameter and dwMaximumSizeHigh are 0 (zero),
    // the maximum size of the file mapping object is equal
    // to the current size of the file that hFile identifies.
    let mapping_handle: HANDLE =
        CreateFileMappingW(file_handle, null_mut(), PAGE_READONLY, 0, 0, null_mut());

    if mapping_handle == INVALID_HANDLE_VALUE || mapping_handle == 0 {
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    log::debug!("Mapping handle: {}", mapping_handle);

    // If dwNumberOfBytesToMap is 0 (zero), the mapping extends
    // from the specified offset to the end of the file mapping
    let mapped_view_handle = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);

    if mapped_view_handle == 0 {
        CloseHandle(mapping_handle);
        return Err(GetLastError());
    }

    #[cfg(feature = "debug")]
    log::debug!("Mapped view address: {:#x}", mapped_view_handle);

    #[cfg(feature = "debug")]
    {
        use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        VirtualQueryEx(
            GetCurrentProcess(),
            mapped_view_handle as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        log::debug!("File mapping size: {}", mbi.RegionSize);
    }

    CloseHandle(mapping_handle);

    Ok(mapped_view_handle)
}

pub unsafe fn get_image_entry_point_rva(file_handle: HANDLE) -> Result<u32, u32> {
    let mut _entry_point_rva: u32 = 0;

    let mapped_view_handle = get_file_mapped_view_handle(file_handle)?;

    let ptr_image_dos_header = mapped_view_handle as *mut IMAGE_DOS_HEADER;
    if (*ptr_image_dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        CloseHandle(mapped_view_handle);
        return Err(ERROR_INVALID_IMAGE_HASH);
    }

    let ptr_image_nt_header = (mapped_view_handle as usize
        + (*ptr_image_dos_header).e_lfanew as usize)
        as *mut IMAGE_NT_HEADERS32;
    if (*ptr_image_nt_header).Signature != IMAGE_NT_SIGNATURE {
        CloseHandle(mapped_view_handle);
        return Err(ERROR_INVALID_IMAGE_HASH);
    }

    if (*ptr_image_nt_header).OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        _entry_point_rva = (*ptr_image_nt_header).OptionalHeader.AddressOfEntryPoint;
    } else if (*ptr_image_nt_header).OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        let ptr_image_nt_header64 = ptr_image_nt_header as *mut IMAGE_NT_HEADERS64;
        _entry_point_rva = (*ptr_image_nt_header64).OptionalHeader.AddressOfEntryPoint;
    } else {
        CloseHandle(mapped_view_handle);
        return Err(ERROR_INVALID_IMAGE_HASH);
    }

    #[cfg(feature = "debug")]
    log::debug!("RVA of image entry point: {:#x}", _entry_point_rva);

    CloseHandle(mapped_view_handle);
    return Ok(_entry_point_rva);
}

pub unsafe fn fill_buffer_with_pattern(pattern: &[u8], length: usize) -> Vec<u8> {
    let mut buffer_with_pattern = Vec::<u8>::new();

    let mut bytes_remaining = length;
    let pattern_len = pattern.len();

    while bytes_remaining > 0 {
        let len = if pattern_len > bytes_remaining {
            bytes_remaining
        } else {
            pattern_len
        };
        buffer_with_pattern.extend_from_slice(&pattern[..len]);
        bytes_remaining -= len;
    }

    buffer_with_pattern
}

pub unsafe fn get_process_basic_info(
    process_handle: HANDLE,
) -> Result<PROCESS_BASIC_INFORMATION, i32> {
    let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
    let ntstatus = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        null_mut(),
    );

    if !NT_SUCCESS(ntstatus) {
        return Err(ntstatus);
    }

    return Ok(pbi);
}

pub unsafe fn write_remote_process_parameters(
    process_handle: HANDLE,
    image_file_name: &str,
    _dll_path: Option<&str>,
    _current_directory: Option<&str>,
    command_line: Option<&str>,
    environment_block: *mut ntapi::winapi::ctypes::c_void,
    windows_title: Option<&str>,
    desktop_info: Option<&str>,
    _shell_info: Option<&str>,
    _runtime_data: Option<&str>,
) -> Result<(), i32> {
    let pbi = get_process_basic_info(process_handle)?;

    let mut image_file_name = str_to_unicode_string(Some(image_file_name));
    let mut command_line = str_to_unicode_string(command_line);
    let mut windows_title = str_to_unicode_string(windows_title);
    let mut desktop_info = str_to_unicode_string(desktop_info);

    let mut params =
        &mut std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>() as *mut RTL_USER_PROCESS_PARAMETERS;

    let ntstatus = RtlCreateProcessParametersEx(
        &mut params as *mut *mut RTL_USER_PROCESS_PARAMETERS,
        &mut image_file_name,
        null_mut(),
        null_mut(),
        &mut command_line,
        environment_block,
        &mut windows_title,
        &mut desktop_info,
        null_mut(),
        null_mut(),
        0,
    );

    if !NT_SUCCESS(ntstatus) {
        return Err(ntstatus);
    }

    let len = (*params).MaximumLength as usize + (*params).EnvironmentSize;

    #[cfg(feature = "debug")]
    log::debug!("Parameters maximum length + size of environment: {}", len);

    let mut ptr_remote_memory = VirtualAllocEx(
        process_handle,
        null_mut(),
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if ptr_remote_memory.is_null() {
        return Err(GetLastError() as i32);
    }

    #[cfg(feature = "debug")]
    {
        log::debug!(
            "Allocated memory in remote process: {:p}",
            ptr_remote_memory
        );
        log::debug!("Param env local address: {:p}", (*params).Environment);
    }
    if (*params).Environment != null_mut() {
        (*params).Environment = (ptr_remote_memory as usize + (*params).Length as usize)
            as *mut ntapi::winapi::ctypes::c_void;
    }

    #[cfg(feature = "debug")]
    log::debug!("Param env remote address: {:p}", (*params).Environment);

    let mut bytes_written: usize = 0;
    if WriteProcessMemory(
        process_handle,
        ptr_remote_memory,
        params as *mut c_void,
        len,
        &mut bytes_written,
    ) == 0
    {
        return Err(GetLastError() as i32);
    }

    #[cfg(feature = "debug")]
    log::debug!("Bytes of env written to remote address: {}", bytes_written);

    let ptr_to_ptr_remote_memory = &mut ptr_remote_memory as *mut *mut c_void;
    let remote_params = pbi.PebBaseAddress as usize + FIELD_OFFSET!(PEB, ProcessParameters);

    // WriteProcessMemory dont accept pointer to pointer, therefore use custom variant
    let kernel32 = GetModuleHandleA("KERNEL32.DLL\0".as_ptr());
    let write_pointer_address_to_memory = std::mem::transmute::<FARPROC, WritePtrAddrToMemory>(
        GetProcAddress(kernel32, "WriteProcessMemory\0".as_ptr()),
    );

    if write_pointer_address_to_memory(
        process_handle,
        remote_params as *mut c_void,
        ptr_to_ptr_remote_memory,
        std::mem::size_of::<*mut c_void>(),
        &mut bytes_written,
    ) == 0
    {
        return Err(GetLastError() as i32);
    }

    #[cfg(feature = "debug")]
    log::debug!(
        "Bytes written of param pointer to remote params: {}",
        bytes_written
    );

    Ok(())
}

pub fn str_to_unicode_string(input: Option<&str>) -> UNICODE_STRING {
    match input {
        Some(input) => {
            let wide_input = str_to_widestring(input);
            let mut unicode_string = UNICODE_STRING::default();
            unsafe { RtlInitUnicodeString(&mut unicode_string, wide_input.as_ptr()) };
            return unicode_string;
        }
        None => {
            return UNICODE_STRING::default();
        }
    }
}

pub fn str_to_widestring(input: &str) -> WideCString {
    return WideCString::from_vec(input.encode_utf16().collect::<Vec<_>>()).unwrap();
}
