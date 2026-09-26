#pragma once
// HandleWrapper.h - RAII wrapper for Windows HANDLE objects
// Ensures handles are properly closed when they go out of scope.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// RAII wrapper for Win32 HANDLE types.
// Automatically calls CloseHandle() on destruction.
class HandleWrapper {
public:
    HandleWrapper() : m_handle(INVALID_HANDLE_VALUE) {}
    explicit HandleWrapper(HANDLE h) : m_handle(h) {}

    ~HandleWrapper() {
        Close();
    }

    // Move semantics
    HandleWrapper(HandleWrapper&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    HandleWrapper& operator=(HandleWrapper&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    // No copying
    HandleWrapper(const HandleWrapper&) = delete;
    HandleWrapper& operator=(const HandleWrapper&) = delete;

    HANDLE Get() const { return m_handle; }

    bool IsValid() const {
        return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
    }

    void Reset(HANDLE h = INVALID_HANDLE_VALUE) {
        Close();
        m_handle = h;
    }

    HANDLE Release() {
        HANDLE h = m_handle;
        m_handle = INVALID_HANDLE_VALUE;
        return h;
    }

private:
    void Close() {
        if (IsValid()) {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE m_handle;
};
