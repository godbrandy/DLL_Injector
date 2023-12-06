#include "injection.h"
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>

#define RELOC_FLAG32(type_offset) ((type_offset >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(type_offset) ((type_offset >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall ShellCode(MANUAL_MAPPING_DATA* data_ptr);

DWORD GetProcessId(const std::wstring& exe_name)
{

    // Create an empty structor of type PROCESSENTRY32
    PROCESSENTRY32 process_entry = { sizeof(PROCESSENTRY32) };

    // Create a snapshot of the processes
    HANDLE snapshot_proc = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL); /////maybe create a unique_ptr with custom deleter
    DWORD proc_id{};

    if (snapshot_proc == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create snapshot.\n";
        return proc_id;
    }

    else
    {
        // Start looping through the processes to find the one of interest
        if (Process32First(snapshot_proc, &process_entry))
        {
            do
            {
                // Compare the name of the process with the name given by the user
                if (_wcsicmp(process_entry.szExeFile, exe_name.data()) == 0)
                {
                    // Return the process ID if the names match
                    proc_id = process_entry.th32ProcessID;
                    return proc_id;
                }

            } while (Process32Next(snapshot_proc, &process_entry));
        }
    }

    return proc_id;
}

bool ManualMap(HANDLE target_proc, const std::wstring& dll_path)
{
    // declare some variables
    std::vector<BYTE> source_data;
    auto dos_header{ std::make_unique<IMAGE_DOS_HEADER>() };
    auto nt_header{ std::make_unique<IMAGE_NT_HEADERS>() };
    std::vector<std::unique_ptr<IMAGE_SECTION_HEADER>> section_header_arr;
    std::unique_ptr<BYTE, VirtualDeallocate> target_alloc;

    // open the dll in binary mode
    std::ifstream input_file(dll_path, std::ios::binary);
    if (!input_file)
    {
        std::print("Couldn't open the file\n");
        return false;
    }

    // read the dos header
    input_file.read((char*)dos_header.get(), sizeof(IMAGE_DOS_HEADER));

    // read the nt header after fixing the position through 'e_lfanew'
    input_file.seekg(dos_header->e_lfanew, std::ios::beg);
    input_file.read((char*)nt_header.get(), sizeof(IMAGE_NT_HEADERS));

    // calculate the number of sections of the PE file
    auto num_sections{ nt_header->FileHeader.NumberOfSections };
    section_header_arr.resize(num_sections);

    // fill the section header array with data from the dll
    for (size_t i{ 0 }; i < num_sections; i++)
    {
        section_header_arr[i] = std::make_unique<IMAGE_SECTION_HEADER>();
        input_file.read((char*)(section_header_arr[i].get()), sizeof(IMAGE_SECTION_HEADER));
    }

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::print("The file isn't a valid PE file\n");
        return false;
    }

    // set the position to the beginning of the file and copy it inside source_data
    input_file.seekg(0, std::ios::beg);
    size_t file_size{ nt_header->OptionalHeader.SizeOfImage };

    source_data.resize(file_size);
    input_file.read((char*)source_data.data(), file_size);
    input_file.close();

    // check if you're in the correct mode
#ifdef _WIN64
    if (nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::print("Bitness doesn't match\n");
        return false;
    }
#else
    if (nt_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::print("Bitness doesn't match\n");
        return false;
    }
#endif

    // allocate memory in the target process 
    target_alloc.reset((BYTE*)VirtualAllocEx(target_proc,
        (void*)nt_header->OptionalHeader.ImageBase,
        file_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));

    // if the preferred address is not available, search for a random one
    if (!target_alloc)
    {
        target_alloc.reset((BYTE*)VirtualAllocEx(target_proc,
            nullptr,
            file_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));

        if (!target_alloc)
        {
            std::print("Failed to allocate memory\n");
            return false;
        }
    }

    // map the dll's sections into the target process's memory
    for (size_t i{ 0 }; i < nt_header->FileHeader.NumberOfSections; i++)
    {
        if (section_header_arr[i]->SizeOfRawData)
        {
            if (!WriteProcessMemory(target_proc,
                target_alloc.get() + section_header_arr[i]->VirtualAddress,
                source_data.data() + section_header_arr[i]->PointerToRawData,
                section_header_arr[i]->SizeOfRawData,
                nullptr))
            {
                std::print("Can't map the sections\n");
                return false;
            }
        }
    }

    // copy address of these functions
    MANUAL_MAPPING_DATA data{};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = (f_GetProcAddress)GetProcAddress;

    // copy addresses of LoadLibrary and GetProcAddress in the header of the dll and map the whole thing into the target process
    memcpy(source_data.data(), &data, sizeof(data));
    WriteProcessMemory(target_proc, target_alloc.get(), source_data.data(), 0x1000, nullptr);

    // alloc space for the shellcode in the target process
    std::unique_ptr<void, VirtualDeallocate> shellcode_alloc(VirtualAllocEx(target_proc,
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));

    if (!shellcode_alloc)
    {
        std::print("Shellcode memory allocation failed\n");
        return false;
    }

    // write the shellcode in the target process
    WriteProcessMemory(target_proc, shellcode_alloc.get(), ShellCode, 0x1000, nullptr);

    // create thread in target process
    HANDLE thread_handle{ CreateRemoteThread(target_proc, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_alloc.get(), target_alloc.get(), 0, nullptr) };

    if (!thread_handle)
    {
        std::print("Thread creation failed\n");
        return false;
    }

    HINSTANCE handle_check{ nullptr };
    while (!handle_check)
    {
        MANUAL_MAPPING_DATA data_checked{ 0 };
        ReadProcessMemory(target_proc, target_alloc.get(), &data_checked, sizeof(data_checked), nullptr);
        handle_check = data_checked.hMod;
        Sleep(10);
    }

    return true;
}

void __stdcall ShellCode(MANUAL_MAPPING_DATA* data_ptr)
{
    if (!data_ptr)
    {
        return;
    }

    // create pointers to optional_header and base of dll
    BYTE* base_ptr{ (BYTE*)data_ptr };
    auto optional_header{ &((IMAGE_NT_HEADERS*)(base_ptr + ((IMAGE_DOS_HEADER*)data_ptr)->e_lfanew))->OptionalHeader };

    // declare some variables
    auto _LoadLibraryA{ data_ptr->pLoadLibraryA };
    auto _GetProcAddress{ data_ptr->pGetProcAddress };
    auto _DllMain{ (f_DLL_ENTRY_POINT)(base_ptr + optional_header->AddressOfEntryPoint) };

    // check if the dll was actually relocated
    BYTE* location_delta{ base_ptr - optional_header->ImageBase };

    // if the dll WAS relocated, fix offsets
    if (location_delta)
    {
        // if the size is zero, we return because there's no data to relocate
        if (!optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            return;

        // get the offset to IBR
        auto reloc_data{ (IMAGE_BASE_RELOCATION*)(base_ptr + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) };

        // while the virtual address is valid
        while (reloc_data->VirtualAddress)
        {
            // subtract the size of IBR (8 bytes) from the total num of bytes
            //  and divide by 2 to find the number of elements in the type_offset array (of WORDs)
            size_t num_entries{ (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) };

            // get offset by adding 8 bytes (size of the first two members)
            WORD* type_offset{ (WORD*)(reloc_data + 1) };

            for (size_t i{ 0 }; i < num_entries; i++, type_offset++)
            {
                // if the relocation flag is of interest, proceed
                if (RELOC_FLAG(*type_offset))
                {
                    // grab the offset by adding base + VA of current relocation block and lower 12 bits of type_offset
                    uintptr_t* patch{ (uintptr_t*)(base_ptr + reloc_data->VirtualAddress + ((*type_offset) & 0xFFF)) };
                    *patch += (uintptr_t)location_delta;
                }
            }
            // go the next relocation block
            reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_data + reloc_data->SizeOfBlock);
        }
    }

    // fix the imports
    // if there is data in the import directory, proceed
    if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        // get offset to IID
        auto import_desc{ (IMAGE_IMPORT_DESCRIPTOR*)(base_ptr + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) };

        // while the name is valid
        while (import_desc->Name)
        {
            // get mod name
            char* module_name{ (char*)(base_ptr + import_desc->Name) };

            // load the import
            HINSTANCE dll_handle{ _LoadLibraryA(module_name) };

            // grab pointers to OFT and FT
            uintptr_t* thunk_addr{ (uintptr_t*)(base_ptr + import_desc->OriginalFirstThunk) };
            uintptr_t* func_addr{ (uintptr_t*)(base_ptr + import_desc->FirstThunk) };

            // if OFT isn't defined, changed it to FT
            if (!thunk_addr)
                thunk_addr = func_addr;

            // while thunk_addr is valid
            for (; *thunk_addr; thunk_addr++, func_addr++)
            {
                // in case the function is called by ordinal
                if (IMAGE_SNAP_BY_ORDINAL(*thunk_addr))
                {
                    *func_addr = _GetProcAddress(dll_handle, (char*)(*thunk_addr & 0xFFFF));
                }
                // in case the function is called by name
                else
                {
                    auto name_import{ (IMAGE_IMPORT_BY_NAME*)(base_ptr + (*thunk_addr)) };
                    *func_addr = _GetProcAddress(dll_handle, name_import->Name);
                }
            }
            import_desc++;
        }
    }

    // if there's data in the TLS directory, proceed
    if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        // get offset to TLS directory
        auto TLS_ptr{ (IMAGE_TLS_DIRECTORY*)(base_ptr + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };
        // get offset to TLS callback
        auto callback{ (PIMAGE_TLS_CALLBACK*)TLS_ptr->AddressOfCallBacks };

        // while callback and *callback are valid
        for (; callback && *callback; callback++)
        {
            // remember that PIMAGE_TLS_CALLBACK* is defined as a function
            (*callback)(base_ptr, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // call dll main
    _DllMain(base_ptr, DLL_PROCESS_ATTACH, nullptr);

    // for checking purposes (optional)
    data_ptr->hMod = (HINSTANCE)base_ptr;
}