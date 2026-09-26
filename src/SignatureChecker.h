#pragma once
// SignatureChecker.h - Authenticode digital signature verification
// Verifies whether a DLL/EXE file has a valid digital signature.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>

// Result of signature verification
enum class SignatureStatus {
    Signed,            // Valid Authenticode signature
    Unsigned,          // No signature present
    InvalidSignature,  // Signature present but invalid
    Error              // Could not determine (access denied, file missing, etc.)
};

namespace SignatureChecker {

    // Verify the Authenticode signature of a file.
    // filePath: full path to the PE file to verify
    // Returns the signature status.
    SignatureStatus VerifyFileSignature(const std::wstring& filePath);

    // Convert SignatureStatus to a human-readable string
    std::string StatusToString(SignatureStatus status);

} // namespace SignatureChecker
