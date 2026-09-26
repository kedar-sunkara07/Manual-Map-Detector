// MemoryScanner.cpp - Virtual memory scanning implementation
// Walks the virtual address space of a process using VirtualQueryEx,
// identifies MEM_PRIVATE executable regions, reads their headers,
// and uses PeDetector to check for manually mapped PE images.

#include "MemoryScanner.h"
#include <sstream>
#include <iomanip>

namespace {

    // Check if a memory protection constant includes execute permission
    bool IsExecutable(DWORD protect) {
        return (protect & PAGE_EXECUTE)            ||
               (protect & PAGE_EXECUTE_READ)       ||
               (protect & PAGE_EXECUTE_READWRITE)  ||
               (protect & PAGE_EXECUTE_WRITECOPY);
    }

    // Check if a memory protection constant includes read permission
    bool IsReadable(DWORD protect) {
        return (protect & PAGE_READONLY)            ||
               (protect & PAGE_READWRITE)           ||
               (protect & PAGE_EXECUTE_READ)        ||
               (protect & PAGE_EXECUTE_READWRITE)   ||
               (protect & PAGE_EXECUTE_WRITECOPY)   ||
               (protect & PAGE_WRITECOPY);
    }

    // Convert protection flags to human-readable string
    std::string ProtectionToString(DWORD protect) {
        // Strip guard/nocache/writecombine modifiers
        DWORD base = protect & 0xFF;

        switch (base) {
            case PAGE_NOACCESS:          return "PAGE_NOACCESS";
            case PAGE_READONLY:          return "PAGE_READONLY";
            case PAGE_READWRITE:         return "PAGE_READWRITE";
            case PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
            case PAGE_EXECUTE:           return "PAGE_EXECUTE";
            case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
            case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
            case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
            default: {
                std::ostringstream ss;
                ss << "0x" << std::hex << protect;
                return ss.str();
            }
        }
    }

    // Convert allocation type to human-readable string
    std::string AllocationTypeToString(DWORD type) {
        std::string result;
        if (type & MEM_IMAGE)   result += "MEM_IMAGE|";
        if (type & MEM_MAPPED)  result += "MEM_MAPPED|";
        if (type & MEM_PRIVATE) result += "MEM_PRIVATE|";

        if (!result.empty() && result.back() == '|') {
            result.pop_back();
        }
        if (result.empty()) {
            std::ostringstream ss;
            ss << "0x" << std::hex << type;
            result = ss.str();
        }
        return result;
    }

    // Minimum region size to consider for PE detection.
    // Anything smaller than ~4KB is unlikely to be a meaningful PE image.
    constexpr SIZE_T MIN_REGION_SIZE = 0x1000;

    // Maximum region size to read for header analysis (first 4KB is enough for PE headers)
    constexpr SIZE_T HEADER_READ_SIZE = 0x1000;

} // anonymous namespace

std::string SuspiciousRegion::GetProtectionString() const {
    return ProtectionToString(protection);
}

std::string SuspiciousRegion::GetAllocationTypeString() const {
    return AllocationTypeToString(allocationType);
}

namespace MemoryScanner {

    std::vector<SuspiciousRegion> ScanProcessMemory(
        HANDLE hProcess,
        const std::vector<ModuleInfo>& modules,
        const std::string& processName,
        DWORD pid)
    {
        std::vector<SuspiciousRegion> findings;

        if (!hProcess) return findings;

        // Walk the entire virtual address space
        SYSTEM_INFO sysInfo = {};
        GetSystemInfo(&sysInfo);

        uintptr_t address = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

        while (address < maxAddress) {
            MEMORY_BASIC_INFORMATION mbi = {};
            SIZE_T queryResult = VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));

            if (queryResult == 0) {
                // Failed to query - advance by page size and try next region
                address += sysInfo.dwPageSize;
                continue;
            }

            // Only examine committed memory
            if (mbi.State == MEM_COMMIT) {
                // Filter: Must be MEM_PRIVATE (not backed by a file or shared mapping)
                bool isPrivate = (mbi.Type == MEM_PRIVATE);

                // Filter: Must have execute permission
                bool isExec = IsExecutable(mbi.Protect);

                // Filter: Must be readable (so we can read the header)
                bool isReadable_ = IsReadable(mbi.Protect);

                // Filter: Must not belong to a known loaded module
                bool isInModule = ModuleScanner::IsAddressInModule(
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress), modules);

                // Filter: Must be large enough to contain a PE
                bool isLargeEnough = (mbi.RegionSize >= MIN_REGION_SIZE);

                // We're interested in: private, executable, not in a module, large enough
                if (isPrivate && isExec && !isInModule && isLargeEnough && isReadable_) {
                    // Read the beginning of the region to check for PE headers
                    SIZE_T readSize = (mbi.RegionSize < HEADER_READ_SIZE)
                        ? mbi.RegionSize
                        : HEADER_READ_SIZE;

                    std::vector<uint8_t> buffer(readSize, 0);
                    SIZE_T bytesRead = 0;

                    BOOL readOk = ReadProcessMemory(
                        hProcess,
                        mbi.BaseAddress,
                        buffer.data(),
                        readSize,
                        &bytesRead
                    );

                    if (readOk && bytesRead > 0) {
                        // Analyze the buffer for PE indicators
                        PeDetectionResult peResult = PeDetector::AnalyzeBuffer(
                            buffer.data(), bytesRead
                        );

                        // Only report if multiple PE indicators are present
                        // This avoids flagging JIT regions, .NET assemblies, etc.
                        if (peResult.isLikelyPe) {
                            SuspiciousRegion region;
                            region.address = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                            region.size = mbi.RegionSize;
                            region.protection = mbi.Protect;
                            region.allocationType = mbi.Type;
                            region.peResult = peResult;
                            region.processName = processName;
                            region.pid = pid;
                            region.severity = Severity::Suspicious;

                            // Build reason list
                            region.reasons.push_back("Executable MEM_PRIVATE region");
                            if (peResult.hasMzHeader)
                                region.reasons.push_back("PE header detected (MZ signature)");
                            if (peResult.hasPeSignature)
                                region.reasons.push_back("PE signature verified");
                            if (peResult.hasValidOptional)
                                region.reasons.push_back("Valid PE Optional Header");
                            if (peResult.hasExecutableSection)
                                region.reasons.push_back("Contains executable sections");
                            if (peResult.hasReasonableSections)
                                region.reasons.push_back("Reasonable section layout");
                            region.reasons.push_back("No corresponding loaded module");

                            findings.push_back(region);
                        }
                    }
                }
            }

            // Advance to the next region
            address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

            // Safety check: ensure we actually advanced
            if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize <= address &&
                mbi.RegionSize == 0) {
                address += sysInfo.dwPageSize;
            }
        }

        return findings;
    }

} // namespace MemoryScanner
