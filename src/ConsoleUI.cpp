// ConsoleUI.cpp - Console user interface implementation

#include "ConsoleUI.h"
#include <iostream>
#include <string>
#include <limits>

namespace ConsoleUI {

    void ShowBanner() {
        std::cout << "\n";
        PrintSeparator('=', 50);
        std::cout << "   * MANUAL MAP DETECTOR by SMOKIE *\n";
        PrintSeparator('=', 50);
        std::cout << "\n";
    }

    int ShowMainMenu() {
        std::cout << "  [1] Emulator Scan\n";
        std::cout << "  [2] Modules Scan\n";
        std::cout << "  [3] Exit\n";
        std::cout << "\n  Select an option: ";

        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) return -1;

        try {
            return std::stoi(input);
        } catch (...) {
            return -1;
        }
    }

    void ShowSectionHeader(const std::string& title) {
        std::cout << "\n";
        PrintSeparator('=', 50);
        std::cout << "  " << title << "\n";
        PrintSeparator('=', 50);
        std::cout << "\n";
    }

    void PrintSeparator(char ch, int width) {
        for (int i = 0; i < width; i++) {
            std::cout << ch;
        }
        std::cout << "\n";
    }

    void PrintSubSeparator(int width) {
        PrintSeparator('-', width);
    }

    void PrintStatus(const std::string& message) {
        std::cout << "  [+] " << message << "\n";
    }

    void PrintWarning(const std::string& message) {
        std::cout << "  [!] " << message << "\n";
    }

    void PrintInfo(const std::string& message) {
        std::cout << "  [*] " << message << "\n";
    }

    void WaitForEnter() {
        std::cout << "\n  Press ENTER to return to the main menu...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    void ClearScreen() {
        // Use Windows API to clear console
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) return;

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

        DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
        DWORD written = 0;
        COORD homeCoord = { 0, 0 };

        FillConsoleOutputCharacterA(hConsole, ' ', cellCount, homeCoord, &written);
        FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, homeCoord, &written);
        SetConsoleCursorPosition(hConsole, homeCoord);
    }

    void SetTitle() {
        SetConsoleTitleA("MANUAL MAP DETECTOR by SMOKIE");
    }

    void PrintResultStatus(const std::string& status) {
        std::cout << "\n";
        PrintSubSeparator(50);
        std::cout << "  STATUS: " << status << "\n";
        PrintSubSeparator(50);
    }

} // namespace ConsoleUI
