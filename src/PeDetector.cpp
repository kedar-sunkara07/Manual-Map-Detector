// PeDetector.cpp - PE header detection and validation implementation
// Performs conservative multi-indicator analysis of memory regions
// to determine if they contain manually mapped PE images.

#include "PeDetector.h"
#include <sstream>
#include <cstring>

std::string PeDetectionResult::GetSummary() const {
    std::ostringstream ss;
    if (hasMzHeader)          ss << "MZ header, ";
    if (hasPeSignature)       ss << "PE signature, ";
    if (hasValidDosHeader)    ss << "Valid DOS header, ";
    if (hasValidOptional)     ss << "Valid Optional header, ";
    if (hasExecutableSection) ss << "Executable section, ";
    if (hasReasonableSections) ss << "Reasonable section layout, ";

    std::string result = ss.str();
    // Remove trailing ", "
    if (result.size() >= 2) {
        result = result.substr(0, result.size() - 2);
    }
    return result;
}

namespace PeDetector {

    bool CheckMzSignature(const uint8_t* buffer, size_t bufferSize) {
        if (bufferSize < 2) return false;
        // Check for 'MZ' (0x4D, 0x5A) at offset 0
        return (buffer[0] == 0x4D && buffer[1] == 0x5A);
    }

    bool CheckPeSignature(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew) {
        // e_lfanew should point within the buffer, with room for the PE signature (4 bytes)
        if (e_lfanew == 0 || e_lfanew > 0x1000) return false; // Unreasonably large offset
        if (static_cast<size_t>(e_lfanew) + 4 > bufferSize) return false;

        // Check for "PE\0\0" signature
        return (buffer[e_lfanew]     == 'P' &&
                buffer[e_lfanew + 1] == 'E' &&
                buffer[e_lfanew + 2] == 0x00 &&
                buffer[e_lfanew + 3] == 0x00);
    }

    bool CheckOptionalHeader(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew) {
        // After PE signature (4 bytes) comes the COFF File Header (20 bytes),
        // then the Optional Header.
        // COFF header offset = e_lfanew + 4
        // Optional header offset = e_lfanew + 4 + 20 = e_lfanew + 24

        size_t coffOffset = static_cast<size_t>(e_lfanew) + 4;
        size_t optOffset = coffOffset + 20;

        // Need at least 2 bytes for the magic number
        if (optOffset + 2 > bufferSize) return false;

        // Check Optional Header magic:
        // 0x10B = PE32 (32-bit)
        // 0x20B = PE32+ (64-bit)
        uint16_t magic = *reinterpret_cast<const uint16_t*>(buffer + optOffset);

        if (magic != 0x10B && magic != 0x20B) return false;

        // For PE32+, check that SizeOfHeaders and SizeOfImage are reasonable
        if (magic == 0x20B) {
            // PE32+ Optional Header is 112 bytes minimum (to SizeOfImage at offset 56)
            if (optOffset + 64 > bufferSize) return true; // Magic is valid, can't check more

            uint32_t sizeOfImage = *reinterpret_cast<const uint32_t*>(buffer + optOffset + 56);
            // SizeOfImage should be > 0 and < 1GB (reasonable for any module)
            if (sizeOfImage == 0 || sizeOfImage > 0x40000000) return false;

            uint32_t sizeOfHeaders = *reinterpret_cast<const uint32_t*>(buffer + optOffset + 60);
            // SizeOfHeaders should be > 0 and less than SizeOfImage
            if (sizeOfHeaders == 0 || sizeOfHeaders > sizeOfImage) return false;
        } else {
            // PE32 Optional Header
            if (optOffset + 64 > bufferSize) return true;

            uint32_t sizeOfImage = *reinterpret_cast<const uint32_t*>(buffer + optOffset + 56);
            if (sizeOfImage == 0 || sizeOfImage > 0x40000000) return false;

            uint32_t sizeOfHeaders = *reinterpret_cast<const uint32_t*>(buffer + optOffset + 60);
            if (sizeOfHeaders == 0 || sizeOfHeaders > sizeOfImage) return false;
        }

        return true;
    }

    bool CheckSections(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew,
                       bool& hasExecutable, bool& hasReasonableCount) {
        hasExecutable = false;
        hasReasonableCount = false;

        size_t coffOffset = static_cast<size_t>(e_lfanew) + 4;

        // Read NumberOfSections from COFF header (offset 2 from COFF start)
        if (coffOffset + 6 > bufferSize) return false;

        uint16_t numSections = *reinterpret_cast<const uint16_t*>(buffer + coffOffset + 2);

        // Reasonable section count: 1 to 96 (max documented by MS)
        if (numSections == 0 || numSections > 96) return false;
        hasReasonableCount = true;

        // Read SizeOfOptionalHeader from COFF header (offset 16 from COFF start)
        if (coffOffset + 20 > bufferSize) return false;
        uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(buffer + coffOffset + 16);

        // Section table starts after Optional Header
        size_t sectionTableOffset = coffOffset + 20 + sizeOfOptionalHeader;

        // Each IMAGE_SECTION_HEADER is 40 bytes
        for (uint16_t i = 0; i < numSections; i++) {
            size_t sectionOffset = sectionTableOffset + (static_cast<size_t>(i) * 40);

            // Need at least the full section header
            if (sectionOffset + 40 > bufferSize) break;

            // Characteristics are at offset 36 within each section header
            uint32_t characteristics = *reinterpret_cast<const uint32_t*>(buffer + sectionOffset + 36);

            // IMAGE_SCN_MEM_EXECUTE = 0x20000000
            if (characteristics & 0x20000000) {
                hasExecutable = true;
            }
        }

        return true;
    }

    PeDetectionResult AnalyzeBuffer(const uint8_t* buffer, size_t bufferSize) {
        PeDetectionResult result;

        if (!buffer || bufferSize < 64) return result; // Too small for any PE

        // Step 1: Check MZ header
        result.hasMzHeader = CheckMzSignature(buffer, bufferSize);
        if (!result.hasMzHeader) return result; // No point continuing without MZ
        result.indicatorCount++;

        // Step 2: Get e_lfanew from DOS header (offset 0x3C)
        if (bufferSize < 0x40) return result;
        DWORD e_lfanew = *reinterpret_cast<const DWORD*>(buffer + 0x3C);

        // Step 3: Validate e_lfanew range
        result.hasValidDosHeader = (e_lfanew > 0 && e_lfanew < 0x1000 &&
                                    static_cast<size_t>(e_lfanew) + 4 <= bufferSize);
        if (result.hasValidDosHeader) result.indicatorCount++;

        // Step 4: Check PE signature
        if (result.hasValidDosHeader) {
            result.hasPeSignature = CheckPeSignature(buffer, bufferSize, e_lfanew);
            if (result.hasPeSignature) result.indicatorCount++;
        }

        // Step 5: Check Optional Header consistency
        if (result.hasPeSignature) {
            result.hasValidOptional = CheckOptionalHeader(buffer, bufferSize, e_lfanew);
            if (result.hasValidOptional) result.indicatorCount++;
        }

        // Step 6: Check sections
        if (result.hasPeSignature) {
            bool hasExec = false, hasReasonable = false;
            if (CheckSections(buffer, bufferSize, e_lfanew, hasExec, hasReasonable)) {
                result.hasExecutableSection = hasExec;
                result.hasReasonableSections = hasReasonable;
                if (hasExec) result.indicatorCount++;
                if (hasReasonable) result.indicatorCount++;
            }
        }

        // Overall assessment: require multiple indicators
        result.isLikelyPe = (result.indicatorCount >= MIN_INDICATORS_FOR_PE);

        return result;
    }

} // namespace PeDetector
