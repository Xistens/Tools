#!/usr/bin/env python3
from ctypes import c_ulong, sizeof, create_string_buffer, byref, windll, c_uint32, c_size_t, GetLastError, WinError
import win32process, win32api, win32con, win32security, winerror
from structure import *
import traceback
import re
import hexdump
"""
References:
https://github.com/MarioVilas/winappdbg
https://github.com/mhammond/pywin32
https://github.com/n1nj4sec/memorpy
https://msdn.microsoft.com
https://docs.python.org/3.6/library/ctypes.html
"""

# --- constants
PSAPI = windll.psapi
KERNEL = windll.kernel32
ADVAPI32 = windll.advapi32

class WinProcess():

    def __init__(self, pid=None):

        if pid:
            self._open(int(pid))

        SystemStruct = self.GetNativeSystemInfo()
        self.max_addr = SystemStruct.lpMaximumApplicationAddress
        self.min_addr = SystemStruct.lpMinimumApplicationAddress

    def __del__(self):
        self.close()

    @staticmethod
    def EnumProcesses():
        """
        Enumerates all active processeses
        """
        process = []
        arr = c_ulong * 256
        pProcessIds = arr()
        cb = sizeof(pProcessIds)
        pBytesReturned = c_ulong()

        # EnumProcesses - Retrieves the process identifier for each process object in the system.
        PSAPI.EnumProcesses(byref(pProcessIds), cb, byref(pBytesReturned))
        # Number of processes returned
        nReturned = int(pBytesReturned.value / sizeof(c_ulong()))

        # Create a list with pids that is nReturned long
        pidProcess = [i for i in pProcessIds][:nReturned]


        hModule = c_ulong()     # An array that receives the list of module handles.
        lpcNeeded = c_ulong()   # The number of bytes required to store all module handles in the lphModule array.
        modname = create_string_buffer(100)#c_buffer(30)
        for pid in pidProcess:
            proc = { "pid": int(pid)}
            # OpenProcess - Opens an existing local process object.
            # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx
            hProcess = KERNEL.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)

            if hProcess:
                # Retrieves a handle for each module in the specified process.
                if PSAPI.EnumProcessModules(hProcess, byref(hModule), sizeof(hModule), byref(lpcNeeded)):
                    PSAPI.GetModuleBaseNameA(hProcess, hModule.value, byref(modname), sizeof(modname))
                    
                    proc["name"] = modname.value
                
                # Close the open object handler
                KERNEL.CloseHandle(hProcess)

            process.append(proc)
        return process
    
    def GetNativeSystemInfo(self):
        """
        Retrieves information about the current system for 64bit system
        @return SystemStruct {Struct} - See structure.py
        """
        SystemStruct = SYSTEM_INFO()
        KERNEL.GetNativeSystemInfo(byref(SystemStruct))

        return SystemStruct
    
    def VirtualQueryEx(self, lpAddress):
        """ 
        Retrieves information about a range of pages within the 
        virtual address space of specified process
        @input lpAddress {LPCVOID}  A pointer to the base address of the region 
                                    of pages to be queried.
        @return mbi {Struct} Memory Basic Information
        
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx
        """
        mbi = MEMORY_BASIC_INFORMATION()
        VirtualQueryEx(self.h_process, lpAddress, byref(mbi), sizeof(mbi))

        return mbi

    def _open(self, dwProcessId):
        """ Open process for this instance """
        # PROCESS_ALL_ACCESS = 2035711
        self.h_process = KERNEL.OpenProcess(win32con.PROCESS_ALL_ACCESS, 0, dwProcessId)
        print(self.h_process)
        if self.h_process != 0:
            self.isProcessOpen = True
            self.pid = dwProcessId
            return True
        return False
    
    def close(self):
        """ Close the open process for this class instance """
        if self.h_process is not None:
            ret = KERNEL.CloseHandle(self.h_process) == 1
            if ret:
                self.h_process = None
                self.pid = None
                self.isProcessOpen = False
            return ret
        return False

    def read_bytes(self, address, bytes=4):
        """
        Read bytes from address

        """
        address = int(address)
        buffer = create_string_buffer(bytes)
        bytesRead = c_size_t(0)
        length = bytes
        data = b""
        while length:
            if ReadProcessMemory(self.h_process, address, byref(buffer), bytes, byref(bytesRead)):
                if bytesRead.value:
                    data += buffer.raw[:bytesRead.value]
                    length -= bytesRead.value
                    address += bytesRead.value
                if not data:
                    print("Error in {0} ReadProcessMemory()".format(GetLastError()))
                    exit(0)

                return data
            else:
                # ERROR_PARTIAL_COPY 299 (0x12B)
                # Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
                # https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382(v=vs.85).aspx
                if GetLastError() == winerror.ERROR_PARTIAL_COPY:
                    data += buffer.raw[:bytesRead.value]
                raise WinError()
        return data

    def iter_region(self, start_offset=None, end_offset=None):
        """
        Generator that gets Memory Basic Information for offset
        """
        offset = start_offset or self.min_addr
        end_offset = end_offset or self.max_addr
        while True:
            if offset >= end_offset:
                break
            
            # VirtualQueryEx provides information about a region of consecutive pages
            # beginning at a specified address
            mbi = self.VirtualQueryEx(offset)
            offset = mbi.BaseAddress
            chunk_size = mbi.RegionSize
            protect = mbi.Protect
            state = mbi.State

            if state & MEM_FREE or state & MEM_RESERVE:
                offset += chunk_size
                continue
            
            yield offset, chunk_size
            offset += chunk_size

    def mem_search(self, value, start_offset=None, end_offset=None):
        """
        Scan through memory
        """
        if not hasattr(self, "isProcessOpen"):
            raise SystemError("No active process to scan.")

        for offset, chunk_size in self.iter_region(start_offset=start_offset, end_offset=end_offset):
            b = b""
            current_offset = offset
            chunk_read = 0
            chunk_exc = False
            while chunk_read < chunk_size:
                try:
                    b += self.read_bytes(current_offset, chunk_size)
                except IOError as e:
                    print(traceback.format_exc())

                    if e.errno == 13:
                        raise
                    chunk_exc = True
                    break
                except Exception as e:
                    print(e)
                    chunk_exc = True
                    break
                finally:
                    current_offset += chunk_size
                    chunk_read += chunk_size
            
            if chunk_exc:
                continue

            if b:
                yield b
        
    @staticmethod
    def get_process_privileges(pid):
        """
        Gets process privileges
        """
        try:
            hProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)

            # open them main process token
            hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_QUERY)

            # retrieve the list of privileges enabled
            privs = win32security.GetTokenInformation(hToken, win32security.TokenPrivileges)

            priv_list = ""
            for i in privs:
                # check if the privilege is enabled
                if i[1] == 3:
                    if priv_list:
                        priv_list += "{0}|".format(win32security.LookupPrivilegeName(None, i[0]))
                    else:
                        priv_list += "{0}".format(win32security.LookupPrivilegeName(None, i[0]))
        except:
            priv_list = "N/A"
        
        return priv_list
    
    @staticmethod
    def get_all_processes(processName=None, privileges=False):
        """
        Get all active processes with or without privileges by using privileges=True
        Can also get all processes by name using processName="name"
        """
        processes = []
        for process in WinProcess.EnumProcesses():
            if processName:
                check = "name" in process and processName.lower() in process["name"].decode("utf-8").lower()
            else:
                check = "name" in process and process["name"] != "?"

            if check:
                if privileges:
                    process["privileges"] = WinProcess.get_process_privileges(process["pid"])

                processes.append(process)

        total = len(processes)
        if total > 0:
            return (total, processes)
            
    @staticmethod
    def print_processes(processName=None, privileges=False):
        """
        Print all active processes
        Can list all active processes with privileges by using privileges=True
        List all active processes by name by using processName="name"
        """
        (total, processes) = WinProcess.get_all_processes(processName, privileges)

        if processes:
            for process in processes:
                privs = ""
                if privileges:
                    privs = ", privileges: " + process["privileges"]
                print("pid: {0}, name: {1}{2}".format(str(process["pid"]), process["name"].decode("utf-8"), privs))
            print("Total: {0}".format(total))
        else:
            print("Unable to retrive active processes...")

def main():
    WinProcess.print_processes(processName="code" ,privileges=True)
    # processes = WinProcess.process_from_name("notepad")
    # print(processes)
    # processes = WinProcess.EnumProcesses()
    # print(processes)
    # mem = WinProcess(5208)

    # for b in mem.mem_search("asd"):
    #     print(len(b))

    # with open("dump.txt", "w") as fh:
    #     for b in mem.mem_search("asd"):
    #         if b:
    #             fh.writelines(hexdump.hexdump(b, result="return"))

if __name__ == "__main__":
    main()