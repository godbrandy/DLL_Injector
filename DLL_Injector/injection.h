#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <print>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = uintptr_t(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
    f_LoadLibraryA		pLoadLibraryA;
    f_GetProcAddress	pGetProcAddress;
    HINSTANCE			hMod;
};

class VirtualDeallocate
{
public:
    VirtualDeallocate(HANDLE proc_handle)
        :
        proc_handle{ proc_handle }
    {}
    VirtualDeallocate() = default;
    void operator()(void* ptr) const
    {
        if (ptr)
        {
            VirtualFreeEx(proc_handle, ptr, 0, MEM_RELEASE);
        }
    }
private:
    HANDLE proc_handle;
};

DWORD GetProcessId(const std::wstring& exe_name);

bool ManualMap(HANDLE target_proc, const std::wstring& dll_name);