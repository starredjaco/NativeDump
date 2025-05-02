# NimDump

NimDump is a port of NativeDump written in Nim, designed to dump the lsass process using only NTAPI functions:

![esquema](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_esquema.png)

- NtOpenProcessToken and NtAdjustPrivilegesToken to enable the SeDebugPrivilege privilege
- NtGetNextProcess and NtQueryInformationProcess to get a handle to the lsass process
- RtlGetVersion to get OS information
- NtReadVirtualMemory and NtQueryInformationProcess to get modules information
- NtQueryVirtualMemory and NtQueryInformationProcess to get memory regions information


The tool supports remapping ntdll.dll using a process created in debug mode. For this it uses the NTAPI functions NtQueryInformationProcess, NtReadVirtualMemory, NtProtectVirtualMemory, NtClose, NtTerminateProcess and NtRemoveProcessDebug; and the Kernel32 function CreateProcessW.

<br>

------------------

## Usage

Compile the binary with:

```
nim c --cpu:amd64 --opt:size --d:release nimdump.nim
```

The syntax is:

```
nimdump.exe [-r] [-o:OUTPUTFILE ]
```

- **Remap ntdll** (-r, optional): Remap the ntdll.dll library

- **Output file** (-o, optional): Dump file name

<br>

By default it creates a file named "n1m.dmp":

```
nimdump.exe
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/nim_1.png)

Using the parameter *-r* allows to remap the ntdll.dll library and *-o* to change the output file name:

```
nimdump.exe -r -o:document.docx
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/nim_2.png)

<br>
