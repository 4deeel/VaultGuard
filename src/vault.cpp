#include "vault.h"
#include "config.h"
#include "timer.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <sys/stat.h>
#include <cerrno>
#include <regex>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <windows.h>
#include <conio.h>
#include <filesystem>
#include <thread>
#include "encryption.h"

using namespace std;
namespace fs = std::filesystem;

void secureClear(string& str) {
    if (!str.empty()) {
        memset(&str[0], 0, str.size());
    }
    str.clear();
}

Vault::Vault(const string& hashFilePath, Logger& loggerRef, const string& vaultFile, 
             const string& activityLogFile, const string& configFilePath)
    : hashFilePath(hashFilePath), loginAttempts(0), lockoutCount(0), isLocked(false), lockoutTime(0), 
      logger(loggerRef), vaultFile(vaultFile), activityLogFile(activityLogFile), configFilePath(configFilePath) {
    // Initialize timeouts from config file
    Config config(configFilePath);
    SESSION_TIMEOUT = config.getSessionTimeout();
    PASSWORD_INPUT_TIMEOUT = config.getPasswordInputTimeout();
    
    if (!createDataDirectory(hashFilePath)) {
        cerr << "Warning: Could not create data directory: " << strerror(errno) << endl;
    }
    readMasterData();
    readSecurityData();
    lastActivity = chrono::system_clock::now();
}

string Vault::generateSalt() const {
    unsigned char salt_bytes[16];
    if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
        throw runtime_error("Failed to generate cryptographic salt");
    }

    stringstream ss;
    for (unsigned char i : salt_bytes) {
        ss << hex << setw(2) << setfill('0') << (int)i;
    }
    return ss.str();
}

string Vault::hashPassword(const string& password, const string& salt) const {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        throw runtime_error("Failed to create hash context");
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to initialize hash");
    }

    if (EVP_DigestUpdate(context, salt.c_str(), salt.length()) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to update hash with salt");
    }

    if (EVP_DigestUpdate(context, password.c_str(), password.length()) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to update hash with password");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to finalize hash");
    }

    EVP_MD_CTX_free(context);

    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    memset(hash, 0, EVP_MAX_MD_SIZE);
    return ss.str();
}

string Vault::base64Encode(const string& data) const {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.c_str(), data.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

string Vault::base64Decode(const string& data) const {
    BIO *bio, *b64;
    char buffer[256] = {0};

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(data.c_str(), data.length());
    bio = BIO_push(b64, bio);
    int len = BIO_read(bio, buffer, sizeof(buffer) - 1);
    BIO_free_all(bio);
    return len > 0 ? string(buffer, len) : "";
}

string Vault::generateTOTPSecret() const {
    unsigned char secret[20];
    if (RAND_bytes(secret, sizeof(secret)) != 1) {
        throw runtime_error("Failed to generate TOTP secret");
    }
    return base64Encode(string((char*)secret, sizeof(secret)));
}

string Vault::generateTOTP(const string& secret) const {
    time_t now = time(nullptr);
    uint64_t timeStep = now / 30; // 30-second intervals
    string decodedSecret = base64Decode(secret);

    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int hmacLength = 0;
    HMAC(EVP_sha1(), decodedSecret.c_str(), decodedSecret.length(),
         (unsigned char*)&timeStep, sizeof(timeStep), hmacResult, &hmacLength);

    int offset = hmacResult[hmacLength - 1] & 0x0F;
    uint32_t code = (hmacResult[offset] & 0x7F) << 24 |
                    (hmacResult[offset + 1] & 0xFF) << 16 |
                    (hmacResult[offset + 2] & 0xFF) << 8 |
                    (hmacResult[offset + 3] & 0xFF);
    code = code % 1000000; // 6-digit code
    return to_string(code);
}

bool Vault::createDataDirectory(const string& path) const {
    string dir = path.substr(0, path.find_last_of('/'));
    if (dir.empty()) return true;

    if (CreateDirectoryA(dir.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return true;
    }
    return false;
}

bool Vault::readMasterData() {
    ifstream file(hashFilePath);
    if (file.is_open()) {
        getline(file, masterHash);
        getline(file, salt);
        string attemptsLine;
        if (getline(file, attemptsLine)) {
            try {
                loginAttempts = stoi(attemptsLine);
            } catch (...) {
                loginAttempts = 0;
            }
        }
        string answerHashLine;
        if (getline(file, answerHashLine)) {
            securityAnswerHash = answerHashLine;
        }
        string totpSecretLine;
        if (getline(file, totpSecretLine)) {
            totpSecret = totpSecretLine;
        }
        string lockoutCountLine;
        if (getline(file, lockoutCountLine)) {
            try {
                lockoutCount = stoi(lockoutCountLine);
            } catch (...) {
                lockoutCount = 0;
            }
        }
        string lockoutTimeLine;
        if (getline(file, lockoutTimeLine)) {
            try {
                lockoutTime = stol(lockoutTimeLine);
            } catch (...) {
                lockoutTime = 0;
            }
        }
        file.close();
        return !masterHash.empty() && !salt.empty();
    }
    return false;
}

bool Vault::writeMasterData(const string& hash, const string& newSalt, const string& answerHash, 
                           const string& totpSecret, int attempts, int lockoutCount, time_t lockoutTime) {
    ofstream file(hashFilePath, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Could not create/write to " << hashFilePath << ": " << strerror(errno) << endl;
        return false;
    }
    file << hash << '\n' << newSalt << '\n' << attempts << '\n' << answerHash << '\n' 
         << totpSecret << '\n' << lockoutCount << '\n' << lockoutTime;
    file.close();
    return true;
}

int Vault::getLockoutDuration() const {
    if (loginAttempts < 3) return 0;
    if (loginAttempts < 6) return 120;
    if (loginAttempts < 9) return 300;
    return 600;
}

bool Vault::checkLockout() {
    if (!isLocked) return false;

    auto now = chrono::system_clock::now();
    auto lockoutDuration = chrono::duration_cast<chrono::seconds>(
        now - chrono::system_clock::from_time_t(lockoutTime)).count();
    int duration = getLockoutDuration();

    if (lockoutDuration >= duration) {
        isLocked = false;
        if (loginAttempts >= 10) {
            clearScreen();
            cout << "Maximum attempts reached. Resetting vault...\n";
            logger.logActivity("Security", "Max attempts reached, vault reset");
            fs::remove(hashFilePath);
            fs::remove(vaultFile);
            fs::remove(activityLogFile);
            fs::remove(hashFilePath + ".question.b64");
            loginAttempts = 0;
            lockoutCount = 0;
            lockoutTime = 0;
            writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
            exit(1);
        }
        loginAttempts = 0;
        lockoutCount = 0;
        lockoutTime = 0;
        writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
        clearScreen();
        cout << "Lockout cleared. You can now try logging in.\n";
        logger.logActivity("Security", "Lockout cleared");
        return false;
    }
    clearScreen();
    cout << "System locked. Try again in " << (duration - lockoutDuration) << " seconds.\n";
    logger.logActivity("Security", "System locked", "Attempts: " + to_string(loginAttempts) + 
                      ", Remaining: " + to_string(duration - lockoutDuration) + "s");
    return true;
}

string Vault::getPasswordInput(const string& prompt) const {
    cout << prompt;
    string password;
    auto startTime = chrono::system_clock::now();
    int asterisksDisplayed = 0;

    while (true) {
        auto now = chrono::system_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(now - startTime).count();
        if (elapsed > PASSWORD_INPUT_TIMEOUT) {
            clearScreen();
            cout << "Error: Password input timed out after " << PASSWORD_INPUT_TIMEOUT << " seconds.\n";
            return "";
        }

        if (_kbhit()) {
            char ch = _getch();
            if (ch == '\r') { // Enter key
                cout << endl;
                break;
            } else if (ch == '\b' && !password.empty()) { // Backspace
                password.pop_back();
                if (asterisksDisplayed > 0) {
                    cout << "\b \b";
                    asterisksDisplayed--;
                }
            } else if (isprint(ch) && password.length() < 128) {
                password += ch;
                if (asterisksDisplayed < 10) { // Limit asterisks to 10 to prevent shoulder surfing
                    cout << '*';
                    asterisksDisplayed++;
                }
            }
        }
    }
    return password;
}

bool Vault::isPasswordStrong(const string& password) const {
    if (password.length() < 8 || password.length() > 128) return false;

    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
        else if (ispunct(c)) hasSpecial = true;
    }

    return hasUpper && hasLower && hasDigit && hasSpecial;
}

bool Vault::readSecurityData() {
    string questionFile = hashFilePath + ".question.b64";
    if (fs::exists(questionFile)) {
        ifstream file(questionFile);
        if (file.is_open()) {
            string base64Question;
            getline(file, base64Question);
            securityQuestion = base64Decode(base64Question);
            file.close();
            return !securityQuestion.empty();
        }
    }
    return false;
}

bool Vault::writeSecurityQuestion(const string& question) {
    string questionFile = hashFilePath + ".question.b64";
    ofstream file(questionFile, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Could not write to " << questionFile << endl;
        return false;
    }
    string base64Question = base64Encode(question);
    file << base64Question;
    file.close();
    securityQuestion = question; // Store plain text for display
    return true;
}

void Vault::reEncryptFiles(const string& newPassword) {
    // Re-encrypt passwords.vault
    if (fs::exists(vaultFile)) {
        ifstream file(vaultFile, ios::binary);
        string encryptedData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        string decryptedData = encryption::decrypt(encryptedData, masterPassword);
        string newEncryptedData = encryption::encrypt(decryptedData, newPassword);
        ofstream outFile(vaultFile, ios::binary);
        outFile.write(newEncryptedData.c_str(), newEncryptedData.size());
        outFile.close();
    }

    // Re-encrypt activity.vault
    if (fs::exists(activityLogFile)) {
        ifstream file(activityLogFile, ios::binary);
        string encryptedData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();

        stringstream newEncryptedData;
        string delimiter = "----ENTRY----";
        vector<string> decryptedEntries;

        // Try legacy format first
        if (encryptedData.find(delimiter) == string::npos) {
            try {
                string decryptedData = encryption::decrypt(encryptedData, masterPassword);
                if (!decryptedData.empty()) {
                    decryptedEntries.push_back(decryptedData);
                }
            } catch (const exception& e) {
                cerr << "Warning: Failed to decrypt legacy activity log: " << e.what() << endl;
            }
        } else {
            // Modern format: split by delimiter
            size_t pos = 0;
            string segment;
            while ((pos = encryptedData.find(delimiter)) != string::npos) {
                segment = encryptedData.substr(0, pos);
                if (!segment.empty()) {
                    try {
                        string decryptedSegment = encryption::decrypt(segment, masterPassword);
                        if (!decryptedSegment.empty()) {
                            decryptedEntries.push_back(decryptedSegment);
                        }
                    } catch (const exception& e) {
                        cerr << "Warning: Failed to decrypt activity log segment: " << e.what() << endl;
                    }
                }
                encryptedData.erase(0, pos + delimiter.length());
            }
            // Handle last segment
            if (!encryptedData.empty()) {
                try {
                    string decryptedSegment = encryption::decrypt(encryptedData, masterPassword);
                    if (!decryptedSegment.empty()) {
                        decryptedEntries.push_back(decryptedSegment);
                    }
                } catch (const exception& e) {
                    cerr << "Warning: Failed to decrypt activity log segment: " << e.what() << endl;
                }
            }
        }

        // Re-encrypt each entry
        ofstream outFile(activityLogFile, ios::binary | ios::trunc);
        if (!outFile.is_open()) {
            cerr << "Error: Could not open activity log file for writing.\n";
            return;
        }
        for (size_t i = 0; i < decryptedEntries.size(); ++i) {
            try {
                string newEncryptedEntry = encryption::encrypt(decryptedEntries[i], newPassword);
                outFile.write(newEncryptedEntry.c_str(), newEncryptedEntry.size());
                if (i < decryptedEntries.size() - 1) {
                    outFile << delimiter;
                }
            } catch (const exception& e) {
                cerr << "Warning: Failed to re-encrypt activity log entry: " << e.what() << endl;
            }
        }
        outFile.flush();
        outFile.close();
    }
}

bool Vault::checkSessionTimeout() {
    auto now = chrono::system_clock::now();
    auto elapsed = chrono::duration_cast<chrono::seconds>(now - lastActivity).count();
    if (elapsed > SESSION_TIMEOUT) {
        clearScreen();
        cout << "Session timed out due to inactivity.\n";
        logger.logActivity("Action", "Session timed out");
        masterPassword.clear();
        return true;
    }
    return false;
}

void Vault::updateLastActivity() {
    lastActivity = chrono::system_clock::now();
}

bool Vault::setupMasterPassword() {
    if (readMasterData() && !masterHash.empty()) {
        clearScreen();
        cout << "Error: A vault already exists. Please log in or delete "
             << hashFilePath << " to reset.\n";
        return false;
    }

    clearScreen();
    string password = getPasswordInput("Enter new master password (8+ chars, mixed case, numbers, symbols): ");
    if (password.empty()) {
        clearScreen();
        cout << "Error: Password cannot be empty or timed out.\n";
        return false;
    }

    string confirm = getPasswordInput("Confirm master password: ");
    if (password != confirm) {
        secureClear(password);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Passwords do not match.\n";
        return false;
    }

    if (!isPasswordStrong(password)) {
        secureClear(password);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Password must be 8-128 characters and include:\n"
             << "- Uppercase letters\n- Lowercase letters\n- Numbers\n- Special characters\n";
        return false;
    }

    try {
        string newSalt = generateSalt();
        string hash = hashPassword(password, newSalt);
        string newTOTPSecret = generateTOTPSecret();
        masterPassword = password;
        logger.setMasterPassword(masterPassword);
        secureClear(password);
        secureClear(confirm);

        // Set security question during setup
        clearScreen();
        cout << "Set up a security question for password recovery:\n";
        setSecurityQuestion();

        bool success = writeMasterData(hash, newSalt, securityAnswerHash, newTOTPSecret, 0, 0, 0);
        if (success) {
            clearScreen();
            cout << "Vault setup complete.\n";
            logger.logActivity("Action", "Set up new vault");
            return true;
        }
    } catch (const exception& e) {
        clearScreen();
        cerr << "Error: " << e.what() << endl;
    }

    secureClear(password);
    secureClear(confirm);
    return false;
}

bool Vault::login() {
    if (checkLockout()) return false;
    if (!readMasterData() || masterHash.empty()) {
        clearScreen();
        cout << "Error: No vault found. Please set up a new vault first.\n";
        return false;
    }

    clearScreen();
    string password = getPasswordInput("Enter master password: ");
    if (password.empty()) {
        clearScreen();
        cout << "Error: Password cannot be empty or timed out.\n";
        return false;
    }

    string inputHash = hashPassword(password, salt);
    if (inputHash == masterHash) {
        loginAttempts = 0;
        lockoutCount = 0;
        lockoutTime = 0;
        writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
        masterPassword = password;
        logger.setMasterPassword(masterPassword);
        secureClear(password);
        clearScreen();
        cout << "Authentication successful.\n";
        logger.logActivity("Action", "Logged in");
        logger.logActivity("Security", "Successful login");
        updateLastActivity();
        return true;
    }

    secureClear(password);
    loginAttempts++;
    clearScreen();
    cout << "Incorrect password. Attempts: " << loginAttempts << "\n";
    logger.logActivity("Action", "Failed login attempt", "Attempt #" + to_string(loginAttempts));
    logger.logActivity("Security", "Failed login attempt", "Attempt #" + to_string(loginAttempts));

    if (loginAttempts >= 3) {
        isLocked = true;
        lockoutTime = chrono::system_clock::to_time_t(chrono::system_clock::now());
        logger.logActivity("Security", "Lockout triggered", "Attempts: " + to_string(loginAttempts));
        int duration = getLockoutDuration();
        clearScreen();
        cout << "System locked. Try again in " << duration << " seconds.\n";
    }

    writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);

    // Rate limiting
    this_thread::sleep_for(chrono::seconds(LOGIN_DELAY));
    return false;
}

string Vault::getMasterPassword() const {
    return masterPassword;
}

void Vault::setSecurityQuestion() {
    clearScreen();
    cout << "Enter security question: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getline(cin, securityQuestion);
    string answer = getPasswordInput("Enter answer: ");
    securityAnswerHash = hashPassword(answer, salt); // Hash the answer
    writeSecurityQuestion(securityQuestion);
    writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
    clearScreen();
    cout << "Security question set successfully.\n";
    logger.logActivity("Action", "Set security question");
}

bool Vault::resetPassword() {
    if (!readSecurityData() || securityQuestion.empty()) {
        clearScreen();
        cout << "No security question set. Cannot reset password.\n";
        return false;
    }

    clearScreen();
    cout << "Security Question: " << securityQuestion << "\n";
    string answer = getPasswordInput("Enter answer: ");
    string answerHash = hashPassword(answer, salt);
    if (answerHash != securityAnswerHash) {
        clearScreen();
        cout << "Incorrect answer. Password reset failed.\n";
        logger.logActivity("Security", "Failed password reset attempt", "Incorrect answer");
        return false;
    }

    // 2FA for password reset
    string expectedTOTP = generateTOTP(totpSecret);
    clearScreen();
    cout << "Enter the 6-digit TOTP code (check your authenticator app): ";
    string userTOTP;
    cin >> userTOTP;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    if (userTOTP != expectedTOTP) {
        clearScreen();
        cout << "Invalid TOTP code. Password reset failed.\n";
        logger.logActivity("Security", "Failed password reset attempt", "Invalid TOTP");
        return false;
    }

    clearScreen();
    string newPassword = getPasswordInput("Enter new master password (8+ chars, mixed case, numbers, symbols): ");
    if (newPassword.empty()) {
        clearScreen();
        cout << "Error: Password cannot be empty or timed out.\n";
        return false;
    }

    string confirm = getPasswordInput("Confirm new master password: ");
    if (newPassword != confirm) {
        secureClear(newPassword);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Passwords do not match.\n";
        return false;
    }

    if (!isPasswordStrong(newPassword)) {
        secureClear(newPassword);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Password must be 8-128 characters and include:\n"
             << "- Uppercase letters\n- Lowercase letters\n- Numbers\n- Special characters\n";
        return false;
    }

    try {
        string newSalt = generateSalt();
        string newHash = hashPassword(newPassword, newSalt);
        bool success = writeMasterData(newHash, newSalt, securityAnswerHash, totpSecret, 0, 0, 0);
        reEncryptFiles(newPassword);
        masterPassword = newPassword;
        logger.setMasterPassword(masterPassword);
        secureClear(newPassword);
        secureClear(confirm);
        if (success) {
            clearScreen();
            cout << "Password reset successful.\n";
            logger.logActivity("Action", "Password reset successful");
            logger.logActivity("Security", "Password reset successful");
            return true;
        }
    } catch (const exception& e) {
        clearScreen();
        cerr << "Error: " << e.what() << endl;
    }

    secureClear(newPassword);
    secureClear(confirm);
    return false;
}

bool Vault::changeMasterPassword() {
    if (checkSessionTimeout()) return false;

    clearScreen();
    string newPassword = getPasswordInput("Enter new master password (8+ chars, mixed case, numbers, symbols): ");
    if (newPassword.empty()) {
        clearScreen();
        cout << "Error: Password cannot be empty or timed out.\n";
        return false;
    }

    string confirm = getPasswordInput("Confirm new master password: ");
    if (newPassword != confirm) {
        secureClear(newPassword);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Passwords do not match.\n";
        return false;
    }

    if (!isPasswordStrong(newPassword)) {
        secureClear(newPassword);
        secureClear(confirm);
        clearScreen();
        cout << "Error: Password must be 8-128 characters and include:\n"
             << "- Uppercase letters\n- Lowercase letters\n- Numbers\n- Special characters\n";
        return false;
    }

    try {
        string newSalt = generateSalt();
        string newHash = hashPassword(newPassword, newSalt);
        bool success = writeMasterData(newHash, newSalt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
        reEncryptFiles(newPassword);
        masterPassword = newPassword;
        logger.setMasterPassword(masterPassword);
        secureClear(newPassword);
        secureClear(confirm);
        if (success) {
            clearScreen();
            cout << "Master password changed successfully.\n";
            logger.logActivity("Action", "Changed master password");
            updateLastActivity();
            return true;
        }
    } catch (const exception& e) {
        clearScreen();
        cerr << "Error: " << e.what() << endl;
    }

    secureClear(newPassword);
    secureClear(confirm);
    return false;
}

bool Vault::backupToCloud() {
    // Check if required files exist
    if (!fs::exists(hashFilePath) || !fs::exists(vaultFile)) {
        clearScreen();
        cout << "Error: Required vault files not found for backup.\n";
        logger.logActivity("Action", "Cloud Backup Failed", "Required files not found");
        return false;
    }

    // Prepare command to execute Python backup script
    string questionFile = hashFilePath + ".question.b64";
    string command = "python backup.py \"" + hashFilePath + "\" \"" + vaultFile + "\" \"" + activityLogFile + "\"";
    if (fs::exists(questionFile)) {
        command += " \"" + questionFile + "\"";
    }

    // Execute backup script
    int result = system(command.c_str());
    if (result == 0) {
        clearScreen();
        cout << "Cloud backup successful.\n";
        logger.logActivity("Action", "Cloud Backup", "Successfully backed up to Google Drive");
        return true;
    } else {
        clearScreen();
        cout << "Error: Cloud backup failed. Ensure Python and backup script are configured correctly.\n";
        logger.logActivity("Action", "Cloud Backup Failed", "Backup script returned error code: " + to_string(result));
        return false;
    }
}

void Vault::showAdminPanel() {
    while (true) {
        if (checkSessionTimeout()) {
            clearScreen();
            cout << "Session timed out. Returning to main menu...\n";
            return;
        }
        clearScreen();
        cout << "=== Admin Panel ===\n";
        cout << "1. Change Master Password\n";
        cout << "2. Set Security Question\n";
        cout << "3. Clear Logs\n";
        cout << "4. View Activity Log\n";
        cout << "5. Backup to Cloud\n";
        cout << "6. Exit\n";

        int choice = timer::getChoiceWithTimeout(chrono::seconds(60), [this]() { updateLastActivity(); });
        if (choice == -1) {
            clearScreen();
            cout << "Inactivity timeout. Returning to main menu...\n";
            logger.logActivity("Action", "Inactivity Timeout", "Admin panel timed out");
            return;
        }

        try {
            switch (choice) {
                case 1:
                    if (changeMasterPassword()) {
                        clearScreen();
                        cout << "Master password changed successfully.\n";
                    } else {
                        clearScreen();
                        cout << "Failed to change master password.\n";
                    }
                    break;
                case 2:
                    clearScreen();
                    setSecurityQuestion();
                    clearScreen();
                    cout << "Security question set successfully.\n";
                    break;
                case 3:
                    clearScreen();
                    clearLogs();
                    clearScreen();
                    cout << "All logs cleared successfully.\n";
                    break;
                case 4:
                    clearScreen();
                    cout << logger.getActivityLog();
                    break;
                case 5:
                    if (backupToCloud()) {
                        clearScreen();
                        cout << "Cloud backup successful.\n";
                    } else {
                        clearScreen();
                        cout << "Cloud backup failed.\n";
                    }
                    break;
                case 6:
                    clearScreen();
                    cout << "Returning to main menu...\n";
                    logger.logActivity("Action", "Exit Admin Panel", "Returned to main menu");
                    return;
                default:
                    clearScreen();
                    cout << "Invalid choice. Please select 1-6.\n";
                    logger.logActivity("Action", "Invalid Menu Choice", "Admin panel choice: " + to_string(choice));
            }
        } catch (const exception& e) {
            clearScreen();
            cerr << "Error: " << e.what() << endl;
            logger.logActivity("Action", "Admin Panel Error", string("Exception: ") + e.what());
        }
        updateLastActivity();
    }
}

void Vault::clearLogs() {
    if (checkSessionTimeout()) return;

    logger.clearLog();
    logger.logActivity("Action", "Cleared all logs");
    logger.logActivity("Security", "Cleared all logs");
    updateLastActivity();
}

int Vault::getLoginAttempts() const {
    return loginAttempts;
}

void Vault::setLoginAttempts(int attempts) {
    loginAttempts = attempts;
    writeMasterData(masterHash, salt, securityAnswerHash, totpSecret, loginAttempts, lockoutCount, lockoutTime);
}