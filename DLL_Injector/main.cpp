// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "injection.h"

//bool IsCorrectTargetArchitecture(HANDLE hProc)
//{
//	BOOL bTarget = FALSE;
//	if (!IsWow64Process(hProc, &bTarget))
//	{
//		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
//		return false;
//	}
//
//	BOOL bHost = FALSE;
//	IsWow64Process(GetCurrentProcess(), &bHost);
//
//	return (bTarget == bHost);
//}

int main()
{
	std::wstring dll_path{ L"C:\\path\\to\\file.dll" };	// full path of the dll
	std::wstring proc_name{ L"game.exe" };				// name of process where you want to inject

	DWORD proc_id{ GetProcessId(proc_name) };

	HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);

	if (!ManualMap(proc_handle, dll_path))
	{
		std::print("Something went wrong.\n");
	}

	return 0;
}