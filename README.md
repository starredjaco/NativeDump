# CrystalDump

CrystalDump is a port of NativeDump written in Crystal lang, designed to dump the lsass process using only NTAPI functions:

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

```
crystaldump.exe [-o OUTPUTFILE ] [-r]
```

- **Output file** (-o, optional): Dump file name

- **Remap ntdll** (-r, optional): Remap the ntdll.dll library


<br>

By default it creates a file named "crystal.dmp":

```
crystaldump.exe
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_1.png)


Using the parameter *-r* it remaps the ntdll.dll library:

```
crystaldump.exe -r
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_2.png)


The parameter *-o* is used to change the output file name:

```
crystaldump.exe -r -o document.pptx
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/nativedump/crystal_3.png)

<br>

------------------

## Build

To build the binary, use a command like:

```
crystal build crystaldump.cr --release
```


<br>

-----------------------------

## TrickDump

For an alternative approach that avoids creating a Minidump file, check out [TrickDump](https://github.com/ricardojoserf/trickdump/): it generates three JSON files and a ZIP archive, and the Minidump is reconstructed on the attacker's machine. This can help evade security solutions that monitor for Minidump creation or exfiltration.

If you like Crystal, check the [crystal-flavour](https://github.com/ricardojoserf/TrickDump/tree/crystal-flavour) branch!


<br>

------------------

## References

- [Crystal Malware](https://rastamouse.me/crystal-malware/) by [Rastamouse](https://twitter.com/_rastamouse)
