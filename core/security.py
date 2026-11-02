"""Credential protection.

On Windows, secrets are encrypted with DPAPI (CryptProtectData, scoped to the
current Windows user) before being written to SQLite. Only the current user
on this machine can decrypt them.

On other platforms (development only) a clearly-labelled fallback is used:
values are stored base64-encoded and the UI warns that they are NOT encrypted.
"""
from __future__ import annotations

import base64
import ctypes
import ipaddress
import re

from .configuration import IS_WINDOWS

_ENTROPY = b"TRACEPOINT-v1-credential-store"


if IS_WINDOWS:
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declare signatures so 64-bit pointers are not truncated to int.
    _CryptProtectData = _crypt32.CryptProtectData
    _CryptProtectData.restype = wintypes.BOOL
    _CryptProtectData.argtypes = [ctypes.POINTER(_BLOB), wintypes.LPCWSTR, ctypes.POINTER(_BLOB),
                                  ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_BLOB)]
    _CryptUnprotectData = _crypt32.CryptUnprotectData
    _CryptUnprotectData.restype = wintypes.BOOL
    _CryptUnprotectData.argtypes = [ctypes.POINTER(_BLOB), ctypes.c_void_p, ctypes.POINTER(_BLOB),
                                    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_BLOB)]
    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = [ctypes.c_void_p]
    _LocalFree.restype = ctypes.c_void_p
    _CRYPTPROTECT_UI_FORBIDDEN = 0x01

    def _mkblob(data: bytes) -> tuple[_BLOB, ctypes.Array]:
        """Return (blob, backing_buffer). The caller MUST keep `backing_buffer` referenced
        for as long as the blob is used, or the pointer dangles."""
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _protect(data: bytes) -> bytes:
        in_blob, in_buf = _mkblob(data)           # in_buf kept alive below
        ent_blob, ent_buf = _mkblob(_ENTROPY)
        out = _BLOB()
        if not _CryptProtectData(ctypes.byref(in_blob), "TRACEPOINT", ctypes.byref(ent_blob),
                                 None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise OSError(f"DPAPI CryptProtectData failed (error {ctypes.get_last_error()})")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _LocalFree(out.pbData)
            del in_buf, ent_buf

    def _unprotect(data: bytes) -> bytes:
        in_blob, in_buf = _mkblob(data)
        ent_blob, ent_buf = _mkblob(_ENTROPY)
        out = _BLOB()
        if not _CryptUnprotectData(ctypes.byref(in_blob), None, ctypes.byref(ent_blob),
                                   None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise OSError(f"DPAPI CryptUnprotectData failed (error {ctypes.get_last_error()}; "
                          "credential may have been saved by another Windows user)")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _LocalFree(out.pbData)
            del in_buf, ent_buf


def encryption_mode() -> str:
    return "DPAPI" if IS_WINDOWS else "PLAINTEXT-FALLBACK"


def encrypt_secret(value: str) -> str:
    raw = value.encode("utf-8")
    if IS_WINDOWS:
        return "dpapi:" + base64.b64encode(_protect(raw)).decode()
    return "plain:" + base64.b64encode(raw).decode()


def decrypt_secret(stored: str) -> str:
    kind, _, payload = stored.partition(":")
    data = base64.b64decode(payload)
    if kind == "dpapi":
        if not IS_WINDOWS:
            raise OSError("This credential was encrypted with Windows DPAPI and can only be read on Windows.")
        return _unprotect(data).decode("utf-8")
    return data.decode("utf-8")


def mask(value: str) -> str:
    """Never show a full credential."""
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:3] + "•" * 6 + value[-3:]


# --- input validation ------------------------------------------------------

MAX_INPUT = 512
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_input(text: str) -> str:
    text = _CTRL.sub("", (text or "")).strip()
    if len(text) > MAX_INPUT:
        raise ValueError(f"Input is longer than {MAX_INPUT} characters.")
    return text


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global
