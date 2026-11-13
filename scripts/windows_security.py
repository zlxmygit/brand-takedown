"""Native Windows file ACLs, using the standard-library ctypes bindings."""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
from functools import lru_cache
import os
from pathlib import Path


@lru_cache(maxsize=1)
def _api():
    if os.name != "nt":
        raise OSError("Windows security APIs are available on Windows only")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    declarations = (
        (kernel.GetCurrentProcess, [], w.HANDLE),
        (kernel.CloseHandle, [w.HANDLE], w.BOOL),
        (kernel.LocalFree, [pointer], pointer),
        (kernel.GetDriveTypeW, [w.LPCWSTR], w.UINT),
        (adv.OpenProcessToken, [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL),
        (adv.GetTokenInformation, [w.HANDLE, ctypes.c_int, pointer, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
        (adv.ConvertSidToStringSidW, [pointer, ctypes.POINTER(pointer)], w.BOOL),
        (adv.ConvertStringSecurityDescriptorToSecurityDescriptorW,
         [w.LPCWSTR, w.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(w.DWORD)], w.BOOL),
        (adv.GetSecurityDescriptorDacl,
         [pointer, ctypes.POINTER(w.BOOL), ctypes.POINTER(pointer), ctypes.POINTER(w.BOOL)], w.BOOL),
        (adv.SetNamedSecurityInfoW,
         [w.LPWSTR, ctypes.c_int, w.DWORD, pointer, pointer, pointer, pointer], w.DWORD),
        (adv.GetNamedSecurityInfoW,
         [w.LPCWSTR, ctypes.c_int, w.DWORD, pointer, pointer, pointer, pointer, ctypes.POINTER(pointer)], w.DWORD),
        (adv.ConvertSecurityDescriptorToStringSecurityDescriptorW,
         [pointer, w.DWORD, w.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(w.DWORD)], w.BOOL),
    )
    for function, args, result in declarations:
        function.argtypes = args
        function.restype = result
    return adv, kernel


@lru_cache(maxsize=1)
def current_user_sid() -> str:
    adv, kernel = _api()
    token = w.HANDLE()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        length = w.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        if not length.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(length.value)
        if not adv.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        # TOKEN_USER begins with SID_AND_ATTRIBUTES, whose first field is PSID.
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = ctypes.c_void_p()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def is_remote_drive(path: Path) -> bool:
    return _api()[1].GetDriveTypeW(path.anchor) == 4


def set_private_acl(path: Path, *, directory: bool) -> None:
    """Grant full access to the current user, SYSTEM and local administrators."""
    adv, kernel = _api()
    inheritance = "OICI" if directory else ""
    sddl = "D:P" + "".join(f"(A;{inheritance};FA;;;{sid})" for sid in (current_user_sid(), "SY", "BA"))
    descriptor = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted = w.BOOL(), w.BOOL()
        dacl = ctypes.c_void_p()
        if not adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not present.value or not dacl.value:
            raise OSError("Private ACL is empty")
        result = adv.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None)
        if result:
            raise ctypes.WinError(result)
    finally:
        kernel.LocalFree(descriptor)


def read_dacl(path: Path) -> str:
    """Read actual DACLs for diagnostics and native Windows tests."""
    adv, kernel = _api()
    descriptor, text = ctypes.c_void_p(), ctypes.c_void_p()
    result = adv.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(descriptor))
    if result:
        raise ctypes.WinError(result)
    try:
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.LocalFree(descriptor)
