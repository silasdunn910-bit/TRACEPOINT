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


MASK_DOTS = "•" * 8  # fixed width: the length of a credential is not revealed either
MASK_REVEAL_MIN_LEN = 20   # shorter credentials are masked completely
MASK_REVEAL = 4            # at most the last 4 characters (<= 20% of the shortest revealing value)


def mask(value: str) -> str:
    """Never show a credential. Short values are fully masked; only very long keys show a short tail."""
    if not value:
        return ""
    if len(value) < MASK_REVEAL_MIN_LEN:
        return MASK_DOTS
    return MASK_DOTS + value[-MASK_REVEAL:]


# Values of credentials seen in this process (stored or read). Used to scrub them from any text
# that is logged or persisted, even if a remote service echoes one back in an error message.
_known_secrets: set[str] = set()
_MIN_SECRET_LEN = 6


def register_secret(value: str) -> None:
    if value and len(value) >= _MIN_SECRET_LEN:
        _known_secrets.add(value)


def redact(text: str) -> str:
    """Replace every known credential value in `text` with ***."""
    if not text or not _known_secrets:
        return text
    for secret in sorted(_known_secrets, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, "***")
    return text


# --- input validation ------------------------------------------------------

MAX_INPUT = 512
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_input(text: str) -> str:
    text = _CTRL.sub("", (text or "")).strip()
    if len(text) > MAX_INPUT:
        raise ValueError(f"Input is longer than {MAX_INPUT} characters.")
    return text


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def is_public_ip(value: str) -> bool:
    """True only for a globally routable unicast address.

    Rejects private, loopback, link-local, multicast, unspecified, reserved, documentation,
    carrier-grade NAT and other non-global ranges, and looks through IPv6 forms that embed an
    IPv4 address (IPv4-mapped, 6to4, NAT64) so they cannot smuggle a private IPv4 target.
    Anything that does not parse is not public.
    """
    try:
        ip = ipaddress.ip_address(str(value).strip().split("%")[0])
    except ValueError:
        return False
    if ip.version == 6:
        embedded = ip.ipv4_mapped
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif embedded is None and ip in _SIX_TO_FOUR:
            embedded = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
        elif ip in _NAT64_LOCAL:
            return False
        if embedded is not None:
            return is_public_ip(str(embedded))
    return ip.is_global and not ip.is_multicast
