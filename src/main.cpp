// main.cpp - Entry point for MANUAL MAP DETECTOR by SMOKIE
// A lightweight defensive anti-cheat diagnostic tool for detecting
// suspicious DLL/module loading and possible manually mapped PE images.
//
// This tool is DETECTION ONLY. It does not modify, inject, or terminate
// any process. It only inspects and reports.

#include "ConsoleUI.h"
#include "ProcessScanner.h"
#include "ModuleScanner.h"
#include "MemoryScanner.h"
#include "SignatureChecker.h"
#include "HandleWrapper.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

// ============================================================================
// EMULATOR SCAN (Option 1)
// Targets HD-Player.exe specifically. Checks loaded modules, DLL signatures,
// and suspicious memory regions.
// ============================================================================
void RunEmulatorScan() {
    ConsoleUI::ShowSectionHeader("EMULATOR SCAN");

    const std::string targetProcess = "HD-Player.exe";
    std::cout << "  Target: " << targetProcess << "\n\n";

    ConsoleUI::PrintStatus("Searching for " + targetProcess + "...");
    std::cout << "\n";

    // Try to find the target process
    ProcessInfo procInfo;
    if (!ProcessScanner::FindProcessByName(targetProcess, procInfo)) {
        std::cout << "  " << targetProcess << " is not running.\n";
        ConsoleUI::PrintResultStatus("EMULATOR NOT RUNNING");
        return;
    }

    std::cout << "  PID: " << procInfo.pid << "\n\n";

    // Open the process for reading
    HandleWrapper hProcess(ProcessScanner::OpenProcessForReading(procInfo.pid));
    if (!hProcess.IsValid()) {
        ConsoleUI::PrintWarning("Access denied: Cannot open " + targetProcess);
        ConsoleUI::PrintResultStatus("ACCESS DENIED");
        return;
    }

    // Phase 1: Enumerate loaded modules
    ConsoleUI::PrintStatus("Scanning loaded modules...");
    std::vector<ModuleInfo> modules = ModuleScanner::EnumerateModules(hProcess.Get());

    // Phase 2: Check DLL signatures
    ConsoleUI::PrintStatus("Checking DLL signatures...");
    struct UnsignedDllInfo {
        std::string name;
        std::wstring path;
        std::string statusStr;
    };
    std::vector<UnsignedDllInfo> unsignedDlls;

    for (const auto& mod : modules) {
        if (mod.path.empty()) continue;

        // Only check DLL files (skip the main exe for signature checks)
        std::string lowerName = mod.name;
        for (auto& c : lowerName) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (lowerName.size() >= 4 && lowerName.substr(lowerName.size() - 4) == ".dll") {
            SignatureStatus sigStatus = SignatureChecker::VerifyFileSignature(mod.path);
            if (sigStatus != SignatureStatus::Signed) {
                UnsignedDllInfo udll;
                udll.name = mod.name;
                udll.path = mod.path;
                udll.statusStr = SignatureChecker::StatusToString(sigStatus);
                unsignedDlls.push_back(udll);
            }
        }
    }

    // Phase 3: Scan for suspicious/unmapped memory
    ConsoleUI::PrintStatus("Checking suspicious/unmapped memory...");
    std::vector<SuspiciousRegion> suspiciousRegions = MemoryScanner::ScanProcessMemory(
        hProcess.Get(), modules, procInfo.name, procInfo.pid
    );

    // ========== RESULTS ==========
    std::cout << "\n";
    ConsoleUI::PrintSubSeparator(50);
    std::cout << "  SCAN RESULTS\n";
    ConsoleUI::PrintSubSeparator(50);
    std::cout << "\n";

    std::cout << "  Loaded DLLs       : " << modules.size() << "\n";
    std::cout << "  Unsigned DLLs     : " << unsignedDlls.size() << "\n";
    std::cout << "  Suspicious Maps   : " << suspiciousRegions.size() << "\n";

    // Show unsigned DLLs (informational)
    if (!unsignedDlls.empty()) {
        for (const auto& udll : unsignedDlls) {
            std::cout << "\n";
            ConsoleUI::PrintSubSeparator(50);
            std::cout << "  Unsigned DLL\n";
            ConsoleUI::PrintSubSeparator(50);
            std::cout << "\n";

            std::cout << "  Name   : " << udll.name << "\n";

            // Convert wide path to narrow for display
            char narrowPath[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, udll.path.c_str(), -1,
                                narrowPath, MAX_PATH, nullptr, nullptr);
            std::cout << "  Path   : " << narrowPath << "\n";
            std::cout << "  Status : " << udll.statusStr << "\n";
        }
    }

    // Show suspicious memory regions
    if (!suspiciousRegions.empty()) {
        for (const auto& region : suspiciousRegions) {
            std::cout << "\n";
            ConsoleUI::PrintSubSeparator(50);
            std::cout << "  Potential Manual Map Indicator\n";
            ConsoleUI::PrintSubSeparator(50);
            std::cout << "\n";

            std::ostringstream addrSS, sizeSS;
            addrSS << "0x" << std::uppercase << std::hex << std::setfill('0')
                   << std::setw(16) << region.address;
            sizeSS << "0x" << std::uppercase << std::hex << std::setfill('0')
                   << std::setw(8) << region.size;

            std::cout << "  Address    : " << addrSS.str() << "\n";
            std::cout << "  Size       : " << sizeSS.str() << "\n";
            std::cout << "  Protection : " << region.GetProtectionString() << "\n";
            std::cout << "  Type       : " << region.GetAllocationTypeString() << "\n";
            std::cout << "  Indicators : " << region.peResult.indicatorCount << "\n";
            std::cout << "\n  Reason:\n";
            for (const auto& reason : region.reasons) {
                std::cout << "    - " << reason << "\n";
            }
        }
    }

    // Overall status
    bool isSuspicious = !suspiciousRegions.empty() || !unsignedDlls.empty();
    if (isSuspicious) {
        ConsoleUI::PrintResultStatus("SUSPICIOUS");
    } else {
        ConsoleUI::PrintResultStatus("CLEAN");
    }
}


// ============================================================================
// MODULES SCAN (Option 2)
// Scans all accessible running EXE processes for indicators of manually
// mapped modules.
// ============================================================================
void RunModulesScan() {
    ConsoleUI::ShowSectionHeader("MODULES SCAN");

    ConsoleUI::PrintStatus("Scanning all processes...\n");

    // Enumerate all running processes
    std::vector<ProcessInfo> processes = ProcessScanner::EnumerateProcesses();

    int totalScanned = 0;
    int totalAccessDenied = 0;
    std::vector<SuspiciousRegion> allFindings;

    for (const auto& proc : processes) {
        // Open the process for reading
        HandleWrapper hProcess(ProcessScanner::OpenProcessForReading(proc.pid));

        if (!hProcess.IsValid()) {
            // Access denied - skip silently for most processes, only note it
            totalAccessDenied++;
            continue;
        }

        std::cout << "  [+] " << proc.name << " PID: " << proc.pid << "\n";
        totalScanned++;

        // Enumerate modules for this process
        std::vector<ModuleInfo> modules;
        try {
            modules = ModuleScanner::EnumerateModules(hProcess.Get());
        } catch (...) {
            // Module enumeration failed - process may have exited
            continue;
        }

        // Scan memory for suspicious regions
        std::vector<SuspiciousRegion> findings;
        try {
            findings = MemoryScanner::ScanProcessMemory(
                hProcess.Get(), modules, proc.name, proc.pid
            );
        } catch (...) {
            // Memory scan failed - process may have exited
            continue;
        }

        // Accumulate findings
        for (auto& f : findings) {
            allFindings.push_back(f);
        }
    }

    // ========== RESULTS ==========
    if (!allFindings.empty()) {
        std::cout << "\n";
        ConsoleUI::PrintSubSeparator(50);
        std::cout << "  SUSPICIOUS MEMORY\n";
        ConsoleUI::PrintSubSeparator(50);

        for (const auto& region : allFindings) {
            std::cout << "\n";

            std::ostringstream addrSS, sizeSS;
            addrSS << "0x" << std::uppercase << std::hex << std::setfill('0')
                   << std::setw(16) << region.address;
            sizeSS << "0x" << std::uppercase << std::hex << std::setfill('0')
                   << std::setw(8) << region.size;

            std::cout << "  Process    : " << region.processName << "\n";
            std::cout << "  PID        : " << std::dec << region.pid << "\n";
            std::cout << "  Address    : " << addrSS.str() << "\n";
            std::cout << "  Size       : " << sizeSS.str() << "\n";
            std::cout << "  Protection : " << region.GetProtectionString() << "\n";
            std::cout << "  Type       : " << region.GetAllocationTypeString() << "\n";
            std::cout << "\n  Reason:\n";
            for (const auto& reason : region.reasons) {
                std::cout << "    - " << reason << "\n";
            }
            std::cout << "\n";
            ConsoleUI::PrintSubSeparator(50);
        }
    }

    // Summary
    std::cout << "\n";
    ConsoleUI::PrintSubSeparator(50);
    std::cout << "  SUMMARY\n";
    ConsoleUI::PrintSubSeparator(50);
    std::cout << "\n";
    std::cout << "  Processes Scanned   : " << totalScanned << "\n";
    std::cout << "  Access Denied       : " << totalAccessDenied << "\n";
    std::cout << "  Potential Manual Maps: " << allFindings.size() << "\n";

    if (!allFindings.empty()) {
        ConsoleUI::PrintResultStatus("SUSPICIOUS");
    } else {
        ConsoleUI::PrintResultStatus("CLEAN");
    }
}


// ============================================================================
// MAIN - Entry point and menu loop
// ============================================================================
int main() {
    // Set console title
    ConsoleUI::SetTitle();

    // Main menu loop
    bool running = true;
    while (running) {
        ConsoleUI::ClearScreen();
        ConsoleUI::ShowBanner();

        int choice = ConsoleUI::ShowMainMenu();

        switch (choice) {
            case 1:
                RunEmulatorScan();
                ConsoleUI::WaitForEnter();
                break;

            case 2:
                RunModulesScan();
                ConsoleUI::WaitForEnter();
                break;

            case 3:
                std::cout << "\n  Exiting...\n";
                running = false;
                break;

            default:
                ConsoleUI::PrintWarning("Invalid option. Please select 1-3.");
                ConsoleUI::WaitForEnter();
                break;
        }
    }

    return 0;
}
