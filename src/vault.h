#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <chrono>
#include "logger.h"

class PasswordManager; // Forward declaration

class Vault {
private:
    std::string hashFilePath;
    std::string masterHash;
    std::string salt;
    std::string masterPassword;
    std::string securityQuestion; // Base64-encoded and stored separately
    std::string securityAnswerHash;
    std::string totpSecret; // For 2FA during password reset
    int loginAttempts;
    int lockoutCount; // Track number of lockouts
    bool isLocked;
    time_t lockoutTime;
    std::chrono::system_clock::time_point lastActivity; // For session timeout
    int SESSION_TIMEOUT; // Configurable session timeout (seconds)
    int PASSWORD_INPUT_TIMEOUT; // Configurable password input timeout (seconds)
    const int MAX_ATTEMPTS = 10;
    const int MAX_LOCKOUTS = 3; // Max lockouts before requiring reset
    const int LOGIN_DELAY = 2; // 2 seconds delay after failed attempt
    Logger& logger;
    std::string vaultFile;
    std::string activityLogFile;
    std::string configFilePath;

    std::string generateSalt() const;
    std::string hashPassword(const std::string& password, const std::string& salt) const;
    std::string base64Encode(const std::string& data) const;
    std::string base64Decode(const std::string& data) const;
    std::string generateTOTPSecret() const;
    std::string generateTOTP(const std::string& secret) const;
    bool readMasterData();
    bool writeMasterData(const std::string& hash, const std::string& salt, 
                        const std::string& answerHash, const std::string& totpSecret, 
                        int attempts, int lockoutCount, time_t lockoutTime);
    bool checkLockout();
    int getLockoutDuration() const;
    bool createDataDirectory(const std::string& path) const;
    std::string getPasswordInput(const std::string& prompt) const;
    bool isPasswordStrong(const std::string& password) const;
    bool readSecurityData();
    bool writeSecurityQuestion(const std::string& question);
    void reEncryptFiles(const std::string& newPassword);
    bool checkSessionTimeout();
    

    friend class PasswordManager;

public:
    explicit Vault(const std::string& hashFilePath, Logger& logger, const std::string& vaultFile, 
                   const std::string& activityLogFile, const std::string& configFilePath);
    bool setupMasterPassword();
    bool login();
    std::string getMasterPassword() const;
    void setSecurityQuestion();
    bool resetPassword();
    bool changeMasterPassword();
    void showAdminPanel();
    void clearLogs();
    bool backupToCloud();
    int getLoginAttempts() const;
    void setLoginAttempts(int attempts);
    void updateLastActivity();
};

#endif // VAULT_H