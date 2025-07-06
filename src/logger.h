#ifndef LOGGER_H
#define LOGGER_H

#include <string>

class Logger {
private:
    std::string activityLogFile;
    std::string masterPassword;

public:
    Logger(const std::string& activityLogFile);
    void setMasterPassword(const std::string& password);
    void logActivity(const std::string& type, const std::string& action, const std::string& details = "");
    std::string getActivityLog();
    void clearLog();
};

#endif // LOGGER_H