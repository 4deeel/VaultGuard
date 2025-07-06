#include "generator.h"
#include <iostream>
#include <random>
#include <chrono>
#include <limits>

using namespace std;

bool PasswordGenerator::getUserChoice(const string& prompt) const {
    cout << prompt;
    char choice;
    cin >> choice;
    return (choice == 'y' || choice == 'Y');
}

string PasswordGenerator::generatePassword() {
    cout << "\n=== Password Generator ===\n";
    int length;

    cout << "Enter desired password length (8-128): ";
    cin >> length;

    if (length < 8 || length > 128) {
        cout << "Invalid length. Must be between 8 and 128 characters.\n";
        return "";
    }

    cout << "Include the following in the password:\n";
    bool includeUpper = getUserChoice("1. Uppercase letters (A-Z)? (y/n): ");
    bool includeLower = getUserChoice("2. Lowercase letters (a-z)? (y/n): ");
    bool includeDigits = getUserChoice("3. Digits (0-9)? (y/n): ");
    bool includeSpecial = getUserChoice("4. Special characters (!@#$%^&*())? (y/n): ");

    if (!includeUpper && !includeLower && !includeDigits && !includeSpecial) {
        cout << "Error: At least one character set must be selected.\n";
        return "";
    }

    // Use current time as seed for randomness
    auto now = chrono::system_clock::now();
    auto timestamp = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    mt19937_64 rng(timestamp);

    string chars;
    if (includeUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (includeDigits) chars += "0123456789";
    if (includeSpecial) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    uniform_int_distribution<size_t> dist(0, chars.length() - 1);
    string password;
    for (int i = 0; i < length; ++i) {
        password += chars[dist(rng)];
    }

    cout << "Generated Password: " << password << "\n";
    return password;
}