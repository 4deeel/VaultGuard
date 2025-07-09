#ifndef CONFIG_H
#define CONFIG_H

#include <string>

class Config {
private:
    std::string configFilePath;
    int sessionTimeout; // in seconds
    int passwordInputTimeout; // in seconds
    bool autoBackup;

    void loadConfig();

public:
    explicit Config(const std::string& configFilePath);
    int getSessionTimeout() const;
    int getPasswordInputTimeout() const;
    bool getAutoBackup() const;
    void setSessionTimeout(int timeout);
    void setPasswordInputTimeout(int timeout);
    void setAutoBackup(bool enable);
    void saveConfig();

};

#endif // CONFIG_H
