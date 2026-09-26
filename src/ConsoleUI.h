#pragma once
// ConsoleUI.h - Console user interface utilities
// Handles menus, formatting, and display for the tool.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>

namespace ConsoleUI {

    // Display the main banner/title
    void ShowBanner();

    // Display the main menu and return the user's choice (1-3)
    int ShowMainMenu();

    // Display a section header with title
    void ShowSectionHeader(const std::string& title);

    // Print a separator line
    void PrintSeparator(char ch = '=', int width = 40);

    // Print a sub-separator line
    void PrintSubSeparator(int width = 40);

    // Print a status message with prefix
    void PrintStatus(const std::string& message);

    // Print an error/warning message
    void PrintWarning(const std::string& message);

    // Print an info message
    void PrintInfo(const std::string& message);

    // Wait for the user to press ENTER
    void WaitForEnter();

    // Clear the console screen
    void ClearScreen();

    // Set console title
    void SetTitle();

    // Print a result status (CLEAN, SUSPICIOUS, etc.)
    void PrintResultStatus(const std::string& status);

} // namespace ConsoleUI
