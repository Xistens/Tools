#! python3
from ctypes import Structure, POINTER, sizeof, c_void_p, c_ulong, c_ulonglong, c_size_t, windll
from ctypes.wintypes import *

if sizeof(c_void_p) == 8:
    ULONG_PTR = c_ulonglong
else:
    ULONG_PTR = c_ulong

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", ULONG_PTR),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD)
    ]

# MBI - State:
# Indicates free pages not accessible to the calling process and available to be allocated
MEM_FREE = 65536 # 0x10000
# Indicates reserved pages where a range of the process's virtual address space is reserved
# without any physical storage being allocated.
MEM_RESERVE = 8192 #0x2000

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx
VirtualQueryEx = windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
VirtualQueryEx.restype = c_size_t

ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
ReadProcessMemory = windll.kernel32.ReadProcessMemory