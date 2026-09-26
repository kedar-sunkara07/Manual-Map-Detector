// ProcessScanner.cpp - Process enumeration and lookup implementation
// Uses Windows Toolhelp32 API to snapshot and iterate processes.

#include "ProcessScanner.h"
#include "HandleWrapper.h"
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>

namespace {
    // Case-insensitive string comparison helper
    bool CaseInsensitiveCompare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++) {
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    }
}

namespace ProcessScanner {

    bool FindProcessByName(const std::string& processName, ProcessInfo& outInfo) {
        HandleWrapper snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot.IsValid()) return false;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(snapshot.Get(), &pe)) return false;

        do {
            // Convert wide string to narrow for comparison
            char narrowName[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                                narrowName, MAX_PATH, nullptr, nullptr);

            if (CaseInsensitiveCompare(narrowName, processName)) {
                outInfo.pid = pe.th32ProcessID;
                outInfo.name = narrowName;
                outInfo.wname = pe.szExeFile;
                return true;
            }
        } while (Process32NextW(snapshot.Get(), &pe));

        return false;
    }

    std::vector<ProcessInfo> EnumerateProcesses() {
        std::vector<ProcessInfo> processes;

        HandleWrapper snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot.IsValid()) return processes;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(snapshot.Get(), &pe)) return processes;

        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.wname = pe.szExeFile;

            char narrowName[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1,
                                narrowName, MAX_PATH, nullptr, nullptr);
            info.name = narrowName;

            // Skip System Idle Process (PID 0) and System (PID 4)
            if (info.pid > 4) {
                processes.push_back(info);
            }
        } while (Process32NextW(snapshot.Get(), &pe));

        return processes;
    }

    HANDLE OpenProcessForReading(DWORD pid) {
        // Request minimum permissions for reading memory and querying information.
        // PROCESS_QUERY_INFORMATION: needed for VirtualQueryEx and module enumeration
        // PROCESS_VM_READ: needed for ReadProcessMemory
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );

        // If full query fails, try with limited information rights
        if (!hProcess) {
            hProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pid
            );
        }

        return hProcess;
    }

} // namespace ProcessScanner
