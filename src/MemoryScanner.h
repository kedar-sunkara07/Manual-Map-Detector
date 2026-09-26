#pragma once
// MemoryScanner.h - Virtual memory region scanning
// Walks process virtual address space to find suspicious executable private regions.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>
#include "ModuleScanner.h"
#include "PeDetector.h"

// Severity level for a finding
enum class Severity {
    Clean,
    Information,
    Suspicious
};

// A suspicious memory region finding
struct SuspiciousRegion {
    uintptr_t address = 0;
    size_t size = 0;
    DWORD protection = 0;
    DWORD allocationType = 0;

    PeDetectionResult peResult;
    Severity severity = Severity::Clean;

    std::string processName;
    DWORD pid = 0;

    // Human-readable reason strings
    std::vector<std::string> reasons;

    // Helper to get protection as a string
    std::string GetProtectionString() const;

    // Helper to get allocation type as a string
    std::string GetAllocationTypeString() const;
};

namespace MemoryScanner {

    // Scan a process's virtual memory for suspicious executable private regions
    // that might indicate manually mapped PE images.
    //
    // hProcess: handle to the target process
    // modules: list of normally loaded modules (to exclude known regions)
    // processName: name of the process (for reporting)
    // pid: process ID (for reporting)
    //
    // Returns a vector of SuspiciousRegion findings.
    std::vector<SuspiciousRegion> ScanProcessMemory(
        HANDLE hProcess,
        const std::vector<ModuleInfo>& modules,
        const std::string& processName,
        DWORD pid
    );

} // namespace MemoryScanner
