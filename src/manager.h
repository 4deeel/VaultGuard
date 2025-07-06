#ifndef MANAGER_H
#define MANAGER_H

#include "entry.h"
#include "encryption.h"
#include "vault.h"
#include "logger.h"
#include "generator.h"
#include <vector>
#include <string>


class PasswordManager {
private:
    std::string vaultFile;
    std::vector<Entry> entries;
    Vault& vault;
    Logger& logger;

    bool readVault();
    bool writeVault();

public:
    PasswordManager(const std::string& vaultFile, Vault& vault, Logger& logger);
    bool addEntry(const std::string& website, const std::string& username, 
                  const std::string& password, const std::string& category);
    bool searchEntry(const std::string& website, const std::string& username = "") const;
    bool updateEntry(const std::string& website, const std::string& username, 
                     const std::string& password, const std::string& category);
    bool deleteEntry(const std::string& website, const std::string& username);
    void listEntries() const;
    void showMenu();
    bool copyEntryCredentials(const std::string& website, const std::string& username);
};

#endif // MANAGER_H