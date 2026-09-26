#pragma once
// ModuleScanner.h - Module enumeration for a target process
// Lists loaded DLLs/modules and retrieves their file paths.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>

// Information about a loaded module (DLL) in a process
struct ModuleInfo {
    HMODULE handle = nullptr;
    uintptr_t baseAddress = 0;
    size_t size = 0;
    std::string name;
    std::wstring path;
};

namespace ModuleScanner {

    // Enumerate all loaded modules in the given process.
    // hProcess: handle to the target process (needs PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    // Returns a vector of ModuleInfo structs.
    std::vector<ModuleInfo> EnumerateModules(HANDLE hProcess);

    // Check if a given address falls within any known loaded module's range.
    // address: the base address to check
    // modules: list of loaded modules to compare against
    // Returns true if the address is within a known module.
    bool IsAddressInModule(uintptr_t address, const std::vector<ModuleInfo>& modules);

    // Check if a given address range overlaps with any known loaded module.
    bool IsRangeInModule(uintptr_t address, size_t size, const std::vector<ModuleInfo>& modules);

} // namespace ModuleScanner
