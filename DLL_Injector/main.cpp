// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
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
	std::wstring dll_path;							// full path of the dll
	std::wstring proc_name;							// name of process where you want to inject

	std::cout << "Insert the path to the dll: ";
	std::wcin >> dll_path;
	std::cout << "Insert the name of the process in which you want to inject the dll: ";
	std::wcin >> proc_name;


	DWORD proc_id{ GetProcessId(proc_name) };

	HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);

	if (!ManualMap(proc_handle, dll_path))
	{
		std::print("Something went wrong.\n");
	}

	return 0;
}