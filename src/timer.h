#ifndef TIMER_H
#define TIMER_H

#include <chrono>
#include <functional>
#include <windows.h>
#include <conio.h>

namespace timer {
    int getChoiceWithTimeout(std::chrono::seconds timeout, std::function<void()> updateActivity = [](){});
}

void clearScreen(); // Declare clearScreen function

#endif // TIMER_H