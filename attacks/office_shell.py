"""
Safe Office-to-shell process-lineage demo.

This creates a real cmd.exe process with a running Microsoft Word process as
the parent. It does not use a macro, document payload, PowerShell download,
or encoded command.
"""

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes


PROCESS_CREATE_PROCESS = 0x0080
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.InitializeProcThreadAttributeList.argtypes = [
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
kernel32.UpdateProcThreadAttribute.argtypes = [
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
kernel32.DeleteProcThreadAttributeList.restype = None
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOEX),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL


def find_word():
    candidates = [
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    for name in ("winword.exe", "WINWORD.EXE"):
        from shutil import which
        resolved = which(name)
        if resolved:
            return resolved
    return None


def create_child_with_parent(parent_pid, command_line):
    size = ctypes.c_size_t()
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attribute_list = ctypes.create_string_buffer(size.value)

    startup = STARTUPINFOEX()
    startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
    startup.lpAttributeList = ctypes.cast(attribute_list, wintypes.LPVOID)

    if not kernel32.InitializeProcThreadAttributeList(
        startup.lpAttributeList, 1, 0, ctypes.byref(size)
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    parent_handle_value = kernel32.OpenProcess(PROCESS_CREATE_PROCESS, False, parent_pid)
    if not parent_handle_value:
        raise ctypes.WinError(ctypes.get_last_error())
    parent_handle = ctypes.c_void_p(parent_handle_value)

    try:
        if not kernel32.UpdateProcThreadAttribute(
            startup.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ctypes.byref(parent_handle),
            ctypes.sizeof(parent_handle),
            None,
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        process_information = PROCESS_INFORMATION()
        if not kernel32.CreateProcessW(
            None,
            command_line,
            None,
            None,
            False,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(process_information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        print(f"[SIEM-l] Office shell demo: parent PID {parent_pid}, child PID {process_information.dwProcessId}")
        kernel32.CloseHandle(process_information.hProcess)
        kernel32.CloseHandle(process_information.hThread)
    finally:
        kernel32.DeleteProcThreadAttributeList(startup.lpAttributeList)
        kernel32.CloseHandle(parent_handle_value)


def main():
    word = find_word()
    if not word:
        print("[SIEM-l] Microsoft Word was not found.")
        return 1

    office = subprocess.Popen([word, "/q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)
    if office.poll() is not None:
        print("[SIEM-l] Word exited before the demo child could be launched.")
        return 1

    create_child_with_parent(
        office.pid,
        r'C:\Windows\System32\cmd.exe /d /k echo SIEM-l Office shell demo',
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
