// SignatureChecker.cpp - Authenticode digital signature verification implementation
// Uses WinVerifyTrust to check if PE files are properly signed.

#include "SignatureChecker.h"

#include <wintrust.h>
#include <softpub.h>

// Note: Link against -lwintrust when building with MinGW.
// For MSVC, add wintrust.lib to the linker inputs.

namespace SignatureChecker {

    SignatureStatus VerifyFileSignature(const std::wstring& filePath) {
        if (filePath.empty()) return SignatureStatus::Error;

        // Set up WINTRUST_FILE_INFO structure
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;

        // GUID for Authenticode verification
        GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Set up WINTRUST_DATA structure
        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.pPolicyCallbackData = nullptr;
        trustData.pSIPClientData = nullptr;
        trustData.dwUIChoice = WTD_UI_NONE;           // No UI
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE; // Skip revocation for speed
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.hWVTStateData = nullptr;
        trustData.pwszURLReference = nullptr;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // Don't hit network
        trustData.dwUIContext = 0;

        // Perform verification
        LONG result = WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE),
            &actionGuid,
            &trustData
        );

        // Clean up state data
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE),
            &actionGuid,
            &trustData
        );

        // Interpret result
        switch (result) {
            case ERROR_SUCCESS:
                return SignatureStatus::Signed;

            case TRUST_E_NOSIGNATURE: {
                // Could be unsigned or error accessing the file
                LONG lastError = static_cast<LONG>(GetLastError());
                if (lastError == TRUST_E_NOSIGNATURE ||
                    lastError == TRUST_E_SUBJECT_FORM_UNKNOWN ||
                    lastError == TRUST_E_PROVIDER_UNKNOWN) {
                    return SignatureStatus::Unsigned;
                }
                return SignatureStatus::Error;
            }

            case TRUST_E_EXPLICIT_DISTRUST:
            case TRUST_E_SUBJECT_NOT_TRUSTED:
            case CRYPT_E_SECURITY_SETTINGS:
                return SignatureStatus::InvalidSignature;

            case TRUST_E_BAD_DIGEST:
                return SignatureStatus::InvalidSignature;

            default:
                // Treat other codes as unsigned (common with catalog-signed files)
                // Many legitimate Windows DLLs are catalog-signed, not embedded-signed,
                // so WinVerifyTrust with WTD_CHOICE_FILE may not find them.
                // We report them as unsigned for informational purposes.
                return SignatureStatus::Unsigned;
        }
    }

    std::string StatusToString(SignatureStatus status) {
        switch (status) {
            case SignatureStatus::Signed:           return "SIGNED";
            case SignatureStatus::Unsigned:          return "UNSIGNED";
            case SignatureStatus::InvalidSignature:  return "INVALID SIGNATURE";
            case SignatureStatus::Error:             return "ERROR";
            default:                                return "UNKNOWN";
        }
    }

} // namespace SignatureChecker
