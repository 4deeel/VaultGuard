#include "timer.h"
#include <iostream>
#include <limits>
#include <thread>

namespace timer {
    int getChoiceWithTimeout(std::chrono::seconds timeout, std::function<void()> updateActivity) {
        std::string input;
        auto start = std::chrono::steady_clock::now();
        std::cout << "Enter choice: ";
        while (true) {
            if (_kbhit()) {
                char ch = _getch();
                if (ch == '\r') { // Enter key
                    std::cout << std::endl;
                    try {
                        int choice = std::stoi(input);
                        updateActivity();
                        return choice;
                    } catch (...) {
                        clearScreen();
                        std::cout << "Invalid input. Please enter a number.\n";
                        input.clear();
                        std::cout << "Enter choice: ";
                    }
                } else if (ch == '\b' && !input.empty()) { // Backspace
                    input.pop_back();
                    std::cout << "\b \b";
                } else if (std::isdigit(ch)) {
                    input += ch;
                    std::cout << ch;
                }
            }
            if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start) >= timeout) {
                clearScreen();
                std::cout << "Inactivity timeout (60 seconds). Logging out...\n";
                return -1; // Signal logout
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}