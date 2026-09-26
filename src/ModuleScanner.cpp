// ModuleScanner.cpp - Module enumeration implementation
// Uses EnumProcessModulesEx to list all loaded DLLs in a target process.

#include "ModuleScanner.h"
#include <psapi.h>
#include <algorithm>

namespace ModuleScanner {

    std::vector<ModuleInfo> EnumerateModules(HANDLE hProcess) {
        std::vector<ModuleInfo> modules;

        if (!hProcess) return modules;

        // First, determine how many modules are loaded
        DWORD bytesNeeded = 0;

        // Try LIST_MODULES_ALL to get both 32-bit and 64-bit modules
        if (!EnumProcessModulesEx(hProcess, nullptr, 0, &bytesNeeded, LIST_MODULES_ALL)) {
            // Fallback to standard EnumProcessModules
            if (!EnumProcessModules(hProcess, nullptr, 0, &bytesNeeded)) {
                return modules;
            }
        }

        if (bytesNeeded == 0) return modules;

        DWORD moduleCount = bytesNeeded / sizeof(HMODULE);
        std::vector<HMODULE> hModules(moduleCount);

        // Actually enumerate
        DWORD bytesUsed = 0;
        if (!EnumProcessModulesEx(hProcess, hModules.data(),
                                   static_cast<DWORD>(hModules.size() * sizeof(HMODULE)),
                                   &bytesUsed, LIST_MODULES_ALL)) {
            if (!EnumProcessModules(hProcess, hModules.data(),
                                     static_cast<DWORD>(hModules.size() * sizeof(HMODULE)),
                                     &bytesUsed)) {
                return modules;
            }
        }

        moduleCount = bytesUsed / sizeof(HMODULE);

        for (DWORD i = 0; i < moduleCount; i++) {
            ModuleInfo info;
            info.handle = hModules[i];
            info.baseAddress = reinterpret_cast<uintptr_t>(hModules[i]);

            // Get module file path (wide)
            wchar_t pathBuf[MAX_PATH] = {};
            if (GetModuleFileNameExW(hProcess, hModules[i], pathBuf, MAX_PATH)) {
                info.path = pathBuf;

                // Extract just the filename
                std::wstring wpath = pathBuf;
                size_t lastSlash = wpath.find_last_of(L"\\/");
                std::wstring wname = (lastSlash != std::wstring::npos)
                    ? wpath.substr(lastSlash + 1)
                    : wpath;

                // Convert name to narrow string
                char narrowName[MAX_PATH] = {};
                WideCharToMultiByte(CP_ACP, 0, wname.c_str(), -1,
                                    narrowName, MAX_PATH, nullptr, nullptr);
                info.name = narrowName;
            }

            // Get module size from MODULEINFO
            MODULEINFO modInfo = {};
            if (GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(modInfo))) {
                info.size = modInfo.SizeOfImage;
            }

            modules.push_back(info);
        }

        return modules;
    }

    bool IsAddressInModule(uintptr_t address, const std::vector<ModuleInfo>& modules) {
        for (const auto& mod : modules) {
            if (address >= mod.baseAddress &&
                address < mod.baseAddress + mod.size) {
                return true;
            }
        }
        return false;
    }

    bool IsRangeInModule(uintptr_t address, size_t size, const std::vector<ModuleInfo>& modules) {
        for (const auto& mod : modules) {
            uintptr_t modEnd = mod.baseAddress + mod.size;
            uintptr_t regionEnd = address + size;

            // Check if ranges overlap
            if (address < modEnd && regionEnd > mod.baseAddress) {
                return true;
            }
        }
        return false;
    }

} // namespace ModuleScanner
