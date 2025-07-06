#include "vault.h"
#include "manager.h"
#include "timer.h"
#include "logger.h"
#include "config.h"
#include <iostream>
#include <limits>
#include <memory>

using namespace std;

// Function to clear the screen and display VaultGuard header
void clearScreen() {
    system("cls"); // Clear screen on Windows
    cout << "\n"
         << "======================================\n"
         << "          VAULTGUARD++\n"
         << "======================================\n\n";
}

void clearInputBuffer() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

int main() {
    const string hashFile = "data/master.hash";
    const string vaultFile = "data/passwords.vault";
    const string activityLogFile = "data/activity.vault";
    const string configFile = "data/vaultguard.config";

    // Declare logger outside try block to ensure scope in catch block
    Logger logger(activityLogFile);

    try {
        Config config(configFile);
        Vault vault(hashFile, logger, vaultFile, activityLogFile, configFile);
        unique_ptr<PasswordManager> manager;
        bool loggedIn = false;

        logger.logActivity("Action", "Program Start", "VaultGuard++ launched");

        while (true) {
            clearScreen(); // Clear screen and show header
            cout << "1. Login\n2. Setup New Vault\n3. Forgot Password\n4. Exit\n";
            int choice = timer::getChoiceWithTimeout(chrono::seconds(60));
            if (choice == -1) {
                clearScreen();
                logger.logActivity("Action", "Inactivity Timeout", "Main menu timed out");
                continue; // Timed out due to inactivity
            }

            try {
                switch (choice) {
                    case 1: // Login
                        if (vault.login()) {
                            loggedIn = true;
                            clearScreen();
                            cout << "Login successful! Welcome to VaultGuard++.\n";
                            logger.logActivity("Action", "Logged in", "User authenticated");
                            logger.logActivity("Security", "Successful login");
                            manager = make_unique<PasswordManager>(vaultFile, vault, logger);
                            // Perform automatic backup if enabled
                            if (config.getAutoBackup()) {
                                vault.backupToCloud();
                            }
                            while (loggedIn) {
                                clearScreen();
                                cout << "1. Password Manager\n2. Admin Panel\n3. Logout\n";
                                choice = timer::getChoiceWithTimeout(chrono::seconds(60), [&vault]() { vault.updateLastActivity(); });
                                if (choice == -1) {
                                    loggedIn = false;
                                    manager.reset();
                                    clearScreen();
                                    cout << "Inactivity timeout. Logging out...\n";
                                    logger.logActivity("Action", "Logged out", "Inactivity timeout");
                                    logger.logActivity("Security", "Logged out", "Inactivity timeout");
                                    break; // Logged out due to inactivity
                                }

                                switch (choice) {
                                    case 1: // Password Manager
                                        manager->showMenu();
                                        logger.logActivity("Action", "Access Password Manager", "User opened password manager");
                                        break;
                                    case 2: // Admin Panel
                                        vault.showAdminPanel();
                                        logger.logActivity("Action", "Access Admin Panel", "User opened admin panel");
                                        break;
                                    case 3: // Logout
                                        loggedIn = false;
                                        manager.reset();
                                        clearScreen();
                                        cout << "Logged out successfully.\n";
                                        logger.logActivity("Action", "Logged out", "User logged out");
                                        logger.logActivity("Security", "Logged out");
                                        break;
                                    default:
                                        clearScreen();
                                        cout << "Invalid choice. Please select 1-3.\n";
                                        logger.logActivity("Action", "Invalid Menu Choice", "Main menu choice: " + to_string(choice));
                                }
                            }
                        } else {
                            clearScreen();
                            cout << "Authentication failed.\n";
                            logger.logActivity("Action", "Failed Login", "Authentication failed");
                            logger.logActivity("Security", "Failed Login", "Authentication failed");
                        }
                        break;
                    case 2: // Setup
                        if (vault.setupMasterPassword()) {
                            clearScreen();
                            cout << "Vault setup complete. Please log in to continue.\n";
                            logger.logActivity("Action", "Set up new vault");
                            logger.logActivity("Security", "Vault setup completed");
                        } else {
                            clearScreen();
                            cout << "Vault setup failed.\n";
                            logger.logActivity("Action", "Setup Failed", "Vault setup failed");
                        }
                        break;
                    case 3: // Forgot Password
                        if (vault.resetPassword()) {
                            clearScreen();
                            cout << "Please log in with your new password.\n";
                            logger.logActivity("Action", "Reset master password");
                            logger.logActivity("Security", "Master password reset");
                        } else {
                            clearScreen();
                            cout << "Password reset failed.\n";
                            logger.logActivity("Action", "Password Reset Failed", "Failed to reset master password");
                            logger.logActivity("Security", "Password Reset Failed");
                        }
                        break;
                    case 4: // Exit
                        clearScreen();
                        cout << "Exiting VaultGuard++. Goodbye!\n";
                        logger.logActivity("Action", "Exited application");
                        return 0;
                    default:
                        clearScreen();
                        cout << "Invalid choice. Please select 1-4.\n";
                        logger.logActivity("Action", "Invalid Menu Choice", "Initial menu choice: " + to_string(choice));
                }
            } catch (const exception& e) {
                clearScreen();
                cerr << "Error: " << e.what() << endl;
                logger.logActivity("Action", "Error Occurred", string("Exception: ") + e.what());
            }
        }
    } catch (const exception& e) {
        clearScreen();
        cerr << "Fatal error: " << e.what() << endl;
        logger.logActivity("Action", "Fatal Error", string("Exception: ") + e.what());
        return 1;
    }

    return 0;
}