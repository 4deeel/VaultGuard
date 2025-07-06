#include "manager.h"
#include "generator.h"
#include "timer.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <limits>
#include <filesystem>
#include <windows.h>

using namespace std;
namespace fs = std::filesystem;

PasswordManager::PasswordManager(const string& vaultFile, Vault& vault, Logger& loggerRef)
    : vaultFile(vaultFile), vault(vault), logger(loggerRef) {
    if (!readVault()) {
        cerr << "Warning: Could not read vault file. Starting with empty vault.\n";
        logger.logActivity("Action", "Read Vault Failed", "Starting with empty vault");
        try {
            fs::remove(vaultFile);
        } catch (const fs::filesystem_error& e) {
            cerr << "Error: Could not remove corrupted vault file: " << e.what() << endl;
            logger.logActivity("Action", "Remove Vault Failed", string("Error: ") + e.what());
        }
    } else {
        logger.logActivity("Action", "Read Vault", "Successfully loaded vault entries");
    }
}

bool PasswordManager::readVault() {
    entries.clear();
    if (!fs::exists(vaultFile)) {
        return false;
    }

    ifstream file(vaultFile, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Could not open vault file for reading.\n";
        logger.logActivity("Action", "Open Vault Failed", "Could not open vault file");
        return false;
    }

    string encryptedData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    if (encryptedData.empty()) {
        return false;
    }

    try {
        string decryptedData = encryption::decrypt(encryptedData, vault.getMasterPassword());
        if (decryptedData.empty()) {
            cerr << "Error: Decryption failed, possible invalid vault file or incorrect password.\n";
            logger.logActivity("Action", "Decrypt Vault Failed", "Invalid vault file or incorrect password");
            return false;
        }

        stringstream ss(decryptedData);
        string entryData;
        while (getline(ss, entryData, '\n')) {
            if (!entryData.empty()) {
                try {
                    entries.push_back(Entry::deserialize(entryData));
                } catch (const exception& e) {
                    cerr << "Warning: Skipping invalid entry: " << e.what() << endl;
                    logger.logActivity("Action", "Invalid Entry Skipped", string("Error: ") + e.what());
                }
            }
        }
        return true;
    } catch (const exception& e) {
        cerr << "Error reading vault: " << e.what() << endl;
        logger.logActivity("Action", "Read Vault Error", string("Error: ") + e.what());
        return false;
    }
}

bool PasswordManager::writeVault() {
    stringstream ss;
    for (const auto& entry : entries) {
        ss << entry.serialize() << '\n';
    }
    string plainData = ss.str();

    try {
        string encryptedData = encryption::encrypt(plainData, vault.getMasterPassword());
        ofstream file(vaultFile, ios::binary);
        if (!file.is_open()) {
            cerr << "Error: Could not write to " << vaultFile << endl;
            logger.logActivity("Action", "Write Vault Failed", "Could not open vault file for writing");
            return false;
        }
        file.write(encryptedData.c_str(), encryptedData.size());
        file.close();
        logger.logActivity("Action", "Write Vault", "Successfully saved vault entries");
        return true;
    } catch (const exception& e) {
        cerr << "Error writing vault: " << e.what() << endl;
        logger.logActivity("Action", "Write Vault Error", string("Error: ") + e.what());
        return false;
    }
}

bool PasswordManager::addEntry(const string& website, const string& username, 
                              const string& password, const string& category) {
    if (website.empty() || username.empty() || password.empty()) {
        cout << "Error: Website, username, and password cannot be empty.\n";
        logger.logActivity("Action", "Add Entry Failed", "Empty website, username, or password");
        return false;
    }
    for (const auto& entry : entries) {
        if (entry.getWebsite() == website && entry.getUsername() == username && entry.getPassword() == password) {
            cout << "Error: Entry for website " << website << " with username " << username << " and password already exists.\n";
            logger.logActivity("Action", "Add Entry Failed", "Duplicate entry for website: " + website + ", username: " + username);
            return false;
        }
    }
    entries.emplace_back(website, username, password, category);
    bool success = writeVault();
    if (success) {
        stringstream ss;
        ss << "Website: " << website << ", Username: " << username << ", Category: " << category;
        logger.logActivity("Action", "Added Entry", ss.str());
    } else {
        logger.logActivity("Action", "Add Entry Failed", "Failed to write vault");
    }
    return success;
}

bool PasswordManager::searchEntry(const string& website, const string& username) const {
    bool found = false;
    for (const auto& entry : entries) {
        if ((website.empty() || entry.getWebsite() == website) && 
            (username.empty() || entry.getUsername() == username)) {
            if (!found) {
                cout << "Matching entries found:\n";
                found = true;
            }
            cout << "Website: " << entry.getWebsite() << "\n";
            cout << "Username: " << entry.getUsername() << "\n";
            cout << "Password: " << entry.getPassword() << "\n";
            cout << "Category: " << entry.getCategory() << "\n";
            cout << "--------------------\n";
        }
    }
    if (!found) {
        cout << "No entry found for website: " << website << " and username: " << username << "\n";
        logger.logActivity("Action", "Search Entry", "No entry found for website: " + website + ", username: " + username);
    } else {
        stringstream ss;
        ss << "Website: " << website << ", Username: " << username;
        logger.logActivity("Action", "Search Entry", ss.str());
    }
    return found;
}

bool PasswordManager::copyEntryCredentials(const string& website, const string& username) {
    vector<int> matches;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].getWebsite() == website && (username.empty() || entries[i].getUsername() == username)) {
            matches.push_back(i);
        }
    }

    if (matches.empty()) {
        cout << "No entry found for website: " << website << " and username: " << username << "\n";
        logger.logActivity("Action", "Copy Credentials Failed", "No entry found for website: " + website + ", username: " + username);
        return false;
    }

    int selectedIndex;
    if (matches.size() == 1) {
        selectedIndex = matches[0];
    } else {
        cout << "Multiple entries found for website " << website << ". Select one to copy:\n";
        for (size_t i = 0; i < matches.size(); ++i) {
            const auto& entry = entries[matches[i]];
            cout << i + 1 << ". Username: " << entry.getUsername() << ", Category: " << entry.getCategory() << "\n";
        }
        cout << "Enter selection (1-" << matches.size() << "): ";
        int selection;
        if (!(cin >> selection) || selection < 1 || selection > static_cast<int>(matches.size())) {
            cout << "Invalid selection.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            logger.logActivity("Action", "Copy Credentials Failed", "Invalid selection for website: " + website);
            return false;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        selectedIndex = matches[selection - 1];
    }

    // Copy username and password to clipboard
    string credentials = "Username: " + entries[selectedIndex].getUsername() + "\nPassword: " + entries[selectedIndex].getPassword();
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, credentials.size() + 1);
        if (hMem) {
            char* pMem = static_cast<char*>(GlobalLock(hMem));
            strcpy(pMem, credentials.c_str());
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
            CloseClipboard();
            cout << "Credentials copied to clipboard!\n";
            logger.logActivity("Action", "Copied Credentials", "Website: " + website + ", Username: " + entries[selectedIndex].getUsername());
            return true;
        } else {
            CloseClipboard();
            cout << "Failed to allocate clipboard memory.\n";
            logger.logActivity("Action", "Copy Credentials Failed", "Memory allocation failed");
            return false;
        }
    } else {
        cout << "Failed to open clipboard.\n";
        logger.logActivity("Action", "Copy Credentials Failed", "Could not open clipboard");
        return false;
    }
}

bool PasswordManager::updateEntry(const string& website, const string& username, 
                                 const string& password, const string& category) {
    vector<int> matches;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].getWebsite() == website) {
            matches.push_back(i);
        }
    }

    if (matches.empty()) {
        cout << "No entry found to update for website: " << website << "\n";
        logger.logActivity("Action", "Update Entry Failed", "No entry found for website: " + website);
        return false;
    }

    int selectedIndex;
    if (matches.size() == 1) {
        selectedIndex = matches[0];
    } else {
        cout << "Multiple entries found for website " << website << ". Select one to update:\n";
        for (size_t i = 0; i < matches.size(); ++i) {
            const auto& entry = entries[matches[i]];
            cout << i + 1 << ". Username: " << entry.getUsername() << ", Category: " << entry.getCategory() << "\n";
        }
        cout << "Enter selection (1-" << matches.size() << "): ";
        int selection;
        if (!(cin >> selection) || selection < 1 || selection > static_cast<int>(matches.size())) {
            cout << "Invalid selection.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            logger.logActivity("Action", "Update Entry Failed", "Invalid selection for website: " + website);
            return false;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        selectedIndex = matches[selection - 1];
    }

    Entry oldEntry = entries[selectedIndex];
    entries[selectedIndex] = Entry(website, username, password, category);
    bool success = writeVault();
    if (success) {
        stringstream ss;
        ss << "Old: Website: " << oldEntry.getWebsite() << ", Username: " << oldEntry.getUsername() 
           << ", Category: " << oldEntry.getCategory() << " | New: Website: " << website 
           << ", Username: " << username << ", Category: " << category;
        logger.logActivity("Action", "Updated Entry", ss.str());
    } else {
        logger.logActivity("Action", "Update Entry Failed", "Failed to write vault");
    }
    return success;
}

bool PasswordManager::deleteEntry(const string& website, const string& username) {
    vector<Entry> deletedEntries;
    auto it = remove_if(entries.begin(), entries.end(),
        [&website, &username, &deletedEntries](const Entry& e) {
            if (e.getWebsite() == website && (username.empty() || e.getUsername() == username)) {
                deletedEntries.push_back(e);
                return true;
            }
            return false;
        });
    if (it != entries.end()) {
        entries.erase(it, entries.end());
        bool success = writeVault();
        if (success) {
            for (const auto& entry : deletedEntries) {
                stringstream ss;
                ss << "Website: " << entry.getWebsite() << ", Username: " << entry.getUsername() 
                   << ", Category: " << entry.getCategory();
                logger.logActivity("Action", "Deleted Entry", ss.str());
            }
        } else {
            logger.logActivity("Action", "Delete Entry Failed", "Failed to write vault");
        }
        return success;
    }
    cout << "No entry found to delete for website: " << website << " and username: " << username << "\n";
    logger.logActivity("Action", "Delete Entry Failed", "No entry found for website: " + website + ", username: " + username);
    return false;
}

void PasswordManager::listEntries() const {
    if (entries.empty()) {
        cout << "No entries in vault.\n";
        logger.logActivity("Action", "List Entries", "Vault is empty");
        return;
    }
    cout << "\n=== Vault Entries (" << entries.size() << ") ===\n";
    for (const auto& entry : entries) {
        cout << "Website: " << entry.getWebsite() << "\n";
        cout << "Username: " << entry.getUsername() << "\n";
        cout << "Password: " << entry.getPassword() << "\n";
        cout << "Category: " << entry.getCategory() << "\n";
        cout << "--------------------\n";
    }
    logger.logActivity("Action", "List Entries", "Displayed all vault entries");
}

void PasswordManager::showMenu() {
    PasswordGenerator generator;
    while (true) {
        if (vault.checkSessionTimeout()) {
            clearScreen();
            cout << "Session timed out. Returning to main menu...\n";
            return;
        }
        clearScreen(); // Clear screen and show header
        cout << "=== Password Manager Menu ===\n";
        cout << "1. Add Entry\n2. Search Entry\n3. Update Entry\n";
        cout << "4. Delete Entry\n5. List All Entries\n6. Generate Password\n";
        cout << "7. Copy Credentials to Clipboard\n8. Exit\n";

        int choice = timer::getChoiceWithTimeout(chrono::seconds(60), [this]() { vault.updateLastActivity(); });
        if (choice == -1) {
            clearScreen();
            cout << "Inactivity timeout. Returning to main menu...\n";
            logger.logActivity("Action", "Inactivity Timeout", "Password Manager menu timed out");
            return;
        }

        string website, username, password, category;
        try {
            switch (choice) {
                case 1: // Add Entry
                    clearScreen();
                    cout << "Enter website: ";
                    getline(cin, website);
                    cout << "Enter username: ";
                    getline(cin, username);
                    password = vault.getPasswordInput("Enter password: ");
                    cout << "Enter category (optional): ";
                    getline(cin, category);
                    if (addEntry(website, username, password, category)) {
                        clearScreen();
                        cout << "Entry added successfully!\n";
                    } else {
                        clearScreen();
                        cout << "Failed to add entry.\n";
                    }
                    break;
                case 2: // Search Entry
                    clearScreen();
                    cout << "Enter website to search (press Enter to skip): ";
                    getline(cin, website);
                    cout << "Enter username to search (press Enter to skip): ";
                    getline(cin, username);
                    clearScreen();
                    searchEntry(website, username);
                    break;
                case 3: // Update Entry
                    clearScreen();
                    cout << "Enter website to update: ";
                    getline(cin, website);
                    cout << "Enter new username: ";
                    getline(cin, username);
                    password = vault.getPasswordInput("Enter new password: ");
                    cout << "Enter new category (optional): ";
                    getline(cin, category);
                    if (updateEntry(website, username, password, category)) {
                        clearScreen();
                        cout << "Entry updated successfully!\n";
                    } else {
                        clearScreen();
                        cout << "Failed to update entry.\n";
                    }
                    break;
                case 4: // Delete Entry
                    clearScreen();
                    cout << "Enter website to delete: ";
                    getline(cin, website);
                    cout << "Enter username to delete (press Enter to skip): ";
                    getline(cin, username);
                    if (deleteEntry(website, username)) {
                        clearScreen();
                        cout << "Entry deleted successfully!\n";
                    } else {
                        clearScreen();
                        cout << "Failed to delete entry.\n";
                    }
                    break;
                case 5: // List All Entries
                    clearScreen();
                    listEntries();
                    break;
                case 6: // Generate Password
                    clearScreen();
                    cout << "Enter website: ";
                    getline(cin, website);
                    cout << "Enter username: ";
                    getline(cin, username);
                    cout << "Enter category (optional): ";
                    getline(cin, category);

                    password = generator.generatePassword();
                    if (password.empty()) {
                        clearScreen();
                        cout << "Password generation failed. Entry not added.\n";
                        logger.logActivity("Action", "Generate Password Failed", "Failed to generate password");
                        break;
                    }

                    clearScreen();
                    cout << "Generated password: " << password << "\n";
                    cout << "Would you like to add this password as an entry? (y/n): ";
                    char addChoice;
                    cin >> addChoice;
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    if (addChoice == 'y' || addChoice == 'Y') {
                        if (addEntry(website, username, password, category)) {
                            clearScreen();
                            cout << "Entry added successfully!\n";
                        } else {
                            clearScreen();
                            cout << "Failed to add entry.\n";
                        }
                    } else {
                        clearScreen();
                        cout << "Password not saved.\n";
                        logger.logActivity("Action", "Generate Password", "Generated password not saved");
                    }
                    break;
                case 7: // Copy Credentials
                    clearScreen();
                    cout << "Enter website: ";
                    getline(cin, website);
                    cout << "Enter username (press Enter to skip): ";
                    getline(cin, username);
                    if (copyEntryCredentials(website, username)) {
                        clearScreen();
                        cout << "Credentials copied to clipboard!\n";
                    } else {
                        clearScreen();
                        cout << "Failed to copy credentials.\n";
                    }
                    break;
                case 8: // Exit
                    clearScreen();
                    logger.logActivity("Action", "Exit Password Manager", "Returned to main menu");
                    cout << "Returning to main menu...\n";
                    return;
                default:
                    clearScreen();
                    cout << "Invalid choice. Please select 1-8.\n";
                    logger.logActivity("Action", "Invalid Menu Choice", "Choice: " + to_string(choice));
            }
        } catch (const exception& e) {
            clearScreen();
            cerr << "Error: " << e.what() << endl;
            logger.logActivity("Action", "Menu Error", string("Exception: ") + e.what());
        }
        vault.updateLastActivity();
    }
}