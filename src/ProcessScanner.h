#pragma once
// ProcessScanner.h - Process enumeration and lookup
// Provides utilities to find and enumerate Windows processes.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>

// Information about a running process
struct ProcessInfo {
    DWORD pid = 0;
    std::string name;
    std::wstring wname;
};

namespace ProcessScanner {

    // Find a specific process by name (case-insensitive).
    // Returns true if found, and fills in the ProcessInfo struct.
    bool FindProcessByName(const std::string& processName, ProcessInfo& outInfo);

    // Enumerate all running processes.
    // Returns a vector of ProcessInfo for each discovered process.
    std::vector<ProcessInfo> EnumerateProcesses();

    // Open a process with minimum read/query permissions.
    // Returns a valid HANDLE or nullptr on failure.
    // The caller is responsible for closing the handle.
    HANDLE OpenProcessForReading(DWORD pid);

} // namespace ProcessScanner
