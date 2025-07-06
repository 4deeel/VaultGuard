#include "config.h"
#include <fstream>
#include <sstream>
#include <iostream>

using namespace std;

Config::Config(const string& configFilePath)
    : configFilePath(configFilePath), sessionTimeout(300), passwordInputTimeout(30), autoBackup(false) {
    loadConfig();
}

void Config::loadConfig() {
    ifstream file(configFilePath);
    if (!file.is_open()) {
        // Create default config file
        saveConfig();
        return;
    }

    string line;
    while (getline(file, line)) {
        size_t pos = line.find('=');
        if (pos == string::npos) continue;

        string key = line.substr(0, pos);
        string value = line.substr(pos + 1);

        try {
            if (key == "session_timeout") {
                sessionTimeout = stoi(value);
                if (sessionTimeout < 60) sessionTimeout = 60; // Minimum 1 minute
            } else if (key == "password_input_timeout") {
                passwordInputTimeout = stoi(value);
                if (passwordInputTimeout < 10) passwordInputTimeout = 10; // Minimum 10 seconds
            } else if (key == "auto_backup") {
                autoBackup = (value == "true");
            }
        } catch (const exception& e) {
            cerr << "Warning: Invalid config value for " << key << ": " << e.what() << endl;
        }
    }
    file.close();
}

void Config::saveConfig() {
    ofstream file(configFilePath);
    if (!file.is_open()) {
        cerr << "Error: Could not write to config file: " << configFilePath << endl;
        return;
    }
    file << "session_timeout=" << sessionTimeout << '\n';
    file << "password_input_timeout=" << passwordInputTimeout << '\n';
    file << "auto_backup=" << (autoBackup ? "true" : "false") << '\n';
    file.close();
}

int Config::getSessionTimeout() const {
    return sessionTimeout;
}

int Config::getPasswordInputTimeout() const {
    return passwordInputTimeout;
}

bool Config::getAutoBackup() const {
    return autoBackup;
}

void Config::setSessionTimeout(int timeout) {
    sessionTimeout = (timeout < 60) ? 60 : timeout;
    saveConfig();
}

void Config::setPasswordInputTimeout(int timeout) {
    passwordInputTimeout = (timeout < 10) ? 10 : timeout;
    saveConfig();
}

void Config::setAutoBackup(bool enabled) {
    autoBackup = enabled;
    saveConfig();
}