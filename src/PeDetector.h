#pragma once
// PeDetector.h - Portable Executable header detection and validation
// Checks if a memory region contains a plausible PE image.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

// Result of PE detection analysis on a memory region
struct PeDetectionResult {
    bool hasMzHeader = false;         // "MZ" DOS header signature found
    bool hasPeSignature = false;      // "PE\0\0" signature found
    bool hasValidDosHeader = false;   // e_lfanew points to a valid location
    bool hasValidOptional = false;    // Optional header looks consistent
    bool hasExecutableSection = false; // At least one section marked executable
    bool hasReasonableSections = false; // Section count is plausible
    bool isLikelyPe = false;          // Overall assessment

    int indicatorCount = 0;           // Number of positive indicators

    std::string GetSummary() const;
};

namespace PeDetector {

    // Minimum number of indicators required to consider a region "likely PE"
    constexpr int MIN_INDICATORS_FOR_PE = 4;

    // Analyze a buffer of memory for PE image indicators.
    // buffer: raw bytes read from the target process
    // bufferSize: size of the buffer
    // Returns a PeDetectionResult with individual and aggregate findings.
    PeDetectionResult AnalyzeBuffer(const uint8_t* buffer, size_t bufferSize);

    // Check if a buffer starts with the MZ DOS header signature
    bool CheckMzSignature(const uint8_t* buffer, size_t bufferSize);

    // Check if the DOS header's e_lfanew value is valid and points
    // to a PE signature within the buffer
    bool CheckPeSignature(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew);

    // Check if the COFF/Optional header fields are internally consistent
    bool CheckOptionalHeader(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew);

    // Check if the PE has sections and they are reasonable
    bool CheckSections(const uint8_t* buffer, size_t bufferSize, DWORD e_lfanew,
                       bool& hasExecutable, bool& hasReasonableCount);

} // namespace PeDetector
