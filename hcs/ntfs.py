"""Windows file-system checks: NTFS Alternate Data Streams and cluster (file) slack."""
from __future__ import annotations

import ctypes
import os
import struct
import sys

from .core import HIGH, MEDIUM, LOW, INFO, analyze_text, printable_strings

IS_WINDOWS = sys.platform == "win32"

BENIGN_STREAMS = {"Zone.Identifier", "SmartScreen", "com.dropbox.attrs", "com.dropbox.attributes", "encryptable",
                  "OECustomProperty", "ms-properties", "AFP_AfpInfo", "AFP_Resource", "Afp_AfpInfo", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}"}

if IS_WINDOWS:
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

    k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.FindFirstStreamW.restype = wintypes.HANDLE
    k32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.FindNextStreamW.restype = wintypes.BOOL
    k32.FindClose.argtypes = [wintypes.HANDLE]
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                wintypes.DWORD, wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.DeviceIoControl.restype = wintypes.BOOL
    k32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    k32.GetFileAttributesW.restype = wintypes.DWORD

    INVALID_HANDLE = wintypes.HANDLE(-1).value


def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def list_streams(path):
    if not IS_WINDOWS:
        return []
    data = WIN32_FIND_STREAM_DATA()
    h = k32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)
    if h in (None, INVALID_HANDLE):
        return []
    out = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                out.append((name.split(":")[1], data.StreamSize))
            if not k32.FindNextStreamW(h, ctypes.byref(data)):
                break
    finally:
        k32.FindClose(h)
    return out


def scan_ads(path, report, nested):
    for name, size in list_streams(path):
        try:
            with open(f"{path}:{name}", "rb") as f:
                data = f.read(min(size, 50_000_000))
        except OSError as e:
            report.error(f"Cannot read stream {name}: {e}")
            continue
        if name == "Zone.Identifier":
            txt = data.decode("utf-8", "replace")
            zone = {"3": "Internet", "4": "Restricted", "2": "Trusted", "1": "Intranet", "0": "Local"}
            z = next((zone.get(l.split("=", 1)[1].strip(), "?") for l in txt.splitlines() if l.startswith("ZoneId=")), "?")
            report.add(INFO, "Mark of the Web", f"stream :{name}", f"File was downloaded (zone: {z}). Shows where it came from.", txt)
            continue
        if name in BENIGN_STREAMS or name.startswith(("com.apple.", "{")):
            report.add(INFO, "Alternate data stream", f"stream :{name}", f"Known application stream ({size:,} bytes).")
            continue
        report.add(HIGH, "Hidden alternate data stream", f"stream :{name}",
                   f"NTFS alternate data stream of {size:,} bytes attached to this file - invisible in Explorer and "
                   "doesn't change the file's displayed size.", "\n".join(printable_strings(data, min_len=4, limit=20)))
        analyze_text(report, data.decode("utf-8", "ignore"), f"stream :{name}", hidden=True)
        nested(f"{os.path.basename(path)}:{name}", data)


# --------------------------------------------------------------------------------------
# File slack
# --------------------------------------------------------------------------------------

GENERIC_READ = 0x80000000
SHARE_ALL = 0x7
OPEN_EXISTING = 3
FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073
ERROR_MORE_DATA = 234
ERROR_HANDLE_EOF = 38


def _extents(path):
    h = k32.CreateFileW(path, GENERIC_READ, SHARE_ALL, None, OPEN_EXISTING, 0x02000000, None)
    if h in (None, INVALID_HANDLE):
        raise OSError(ctypes.get_last_error(), "open file")
    try:
        extents, start = [], 0
        while True:
            inp = ctypes.c_longlong(start)
            buf = ctypes.create_string_buffer(65536)
            ret = wintypes.DWORD()
            ok = k32.DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS, ctypes.byref(inp), 8, buf, len(buf), ctypes.byref(ret), None)
            err = ctypes.get_last_error()
            if not ok and err not in (ERROR_MORE_DATA,):
                if err == ERROR_HANDLE_EOF:
                    return None  # resident in the MFT
                raise OSError(err, "FSCTL_GET_RETRIEVAL_POINTERS")
            count = struct.unpack_from("<I", buf.raw, 0)[0]
            cur = struct.unpack_from("<q", buf.raw, 8)[0]
            for i in range(count):
                nxt, lcn = struct.unpack_from("<qq", buf.raw, 16 + i * 16)
                extents.append((cur, nxt, lcn))
                cur = nxt
            if ok:
                return extents
            start = cur
    finally:
        k32.CloseHandle(h)


def _read_volume(drive, offset, size):
    h = k32.CreateFileW(f"\\\\.\\{drive}", GENERIC_READ, 0x3, None, OPEN_EXISTING, 0, None)
    if h in (None, INVALID_HANDLE):
        raise PermissionError(ctypes.get_last_error(), "open volume")
    try:
        if not k32.SetFilePointerEx(h, offset, None, 0):
            raise OSError(ctypes.get_last_error(), "seek volume")
        buf = ctypes.create_string_buffer(size)
        got = wintypes.DWORD()
        if not k32.ReadFile(h, buf, size, ctypes.byref(got), None):
            raise OSError(ctypes.get_last_error(), "read volume")
        return buf.raw[:got.value]
    finally:
        k32.CloseHandle(h)


def scan_slack(path, report):
    """Read the unused tail of the file's last disk cluster. Requires Administrator rights."""
    if not IS_WINDOWS:
        return
    loc = "file slack (disk)"
    path = os.path.abspath(path)
    drive = os.path.splitdrive(path)[0]
    if not drive or drive.startswith("\\\\"):
        report.add(INFO, "File slack not checked", loc, "File is on a network share - slack can only be read on local disks.")
        return
    attrs = k32.GetFileAttributesW(path)
    if attrs != 0xFFFFFFFF and attrs & (0x800 | 0x4000 | 0x400000 | 0x40000 | 0x1000):
        report.add(INFO, "File slack not checked", loc, "File is compressed, encrypted, or a cloud placeholder (e.g. OneDrive) - no readable slack.")
        return
    if not is_admin():
        report.add(INFO, "File slack not checked", loc, "Reading raw disk clusters requires running the scanner as Administrator.")
        return
    try:
        spc, bps, _, _ = (wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD())
        if not k32.GetDiskFreeSpaceW(drive + "\\", ctypes.byref(spc), ctypes.byref(bps), ctypes.byref(_), ctypes.byref(_)):
            raise OSError(ctypes.get_last_error(), "GetDiskFreeSpace")
        cs = spc.value * bps.value
        size = os.path.getsize(path)
        if size == 0:
            return
        if size % cs == 0:
            report.add(INFO, "File slack checked", loc, f"File ends exactly on a {cs:,}-byte cluster boundary - no slack.")
            return
        ext = _extents(path)
        if ext is None:
            report.add(INFO, "File slack not applicable", loc,
                       "Small file stored inside the NTFS Master File Table - it has no cluster slack.")
            return
        last_vcn = (size - 1) // cs
        lcn = None
        for start, nxt, l in ext:
            if start <= last_vcn < nxt:
                lcn = None if l < 0 else l + (last_vcn - start)
                break
        if lcn is None:
            report.add(INFO, "File slack not checked", loc, "Last cluster is sparse/virtual.")
            return
        cluster = _read_volume(drive, lcn * cs, cs)
        tail_len = size - last_vcn * cs
        with open(path, "rb") as f:
            f.seek(last_vcn * cs)
            file_tail = f.read(tail_len)
        if cluster[:tail_len] != file_tail:
            report.add(INFO, "File slack not verified", loc,
                       "On-disk cluster doesn't match the file (pending writes or file system virtualization) - skipped.")
            return
        slack = cluster[tail_len:]
        sector_end = ((tail_len + bps.value - 1) // bps.value) * bps.value - tail_len
        if not slack.strip(b"\x00"):
            report.add(INFO, "File slack checked", loc, f"{len(slack):,} bytes of slack - all zero (clean).")
            return
        strs = printable_strings(slack, min_len=5, limit=30)
        magic = next((n for sig, n in ((b"PK\x03\x04", "ZIP/Office"), (b"%PDF", "PDF"), (b"\xd0\xcf\x11\xe0", "OLE/Office"),
                                       (b"MZ", "Windows executable"), (b"\x89PNG", "PNG"), (b"\xff\xd8\xff", "JPEG"))
                      if sig in slack), None)
        report.add(HIGH if magic or len(strs) > 5 else MEDIUM, "Data in file slack", loc,
                   f"{len(slack.strip(bytes(1))):,} non-zero bytes in the {len(slack):,}-byte slack after the file's end "
                   f"(cluster {lcn:,}). Usually leftovers of previously deleted files on this disk, but slack-hiding tools put data here too."
                   + (f" Contains a {magic} signature." if magic else "")
                   + f" Note: slack is a property of this disk; it does not travel with copies of the file.",
                   "\n".join(strs) if strs else slack[sector_end:sector_end + 256].hex(" "))
        if strs:
            analyze_text(report, "\n".join(strs), loc, hidden=True)
    except PermissionError:
        report.add(INFO, "File slack not checked", loc, "Access to the raw volume was denied (run as Administrator).")
    except Exception as e:
        report.error(f"Slack check failed: {e}")


def relaunch_as_admin():
    """Restart this program elevated (UAC prompt)."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    exe = sys.executable.replace("python.exe", "pythonw.exe") if sys.executable.endswith("python.exe") else sys.executable
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return r > 32
