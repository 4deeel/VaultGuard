#include "logger.h"
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <iostream>
#include "encryption.h"

using namespace std;

Logger::Logger(const string& activityLogFile)
    : activityLogFile(activityLogFile) {}

void Logger::setMasterPassword(const string& password) {
    masterPassword = password;
}

void Logger::logActivity(const string& type, const string& action, const string& details) {
    if (masterPassword.empty()) return;

    time_t now = time(nullptr);
    string timestamp = ctime(&now);
    timestamp.pop_back(); // Remove newline
    string logEntry = timestamp + " | " + type + ": " + action;
    if (!details.empty()) {
        logEntry += " | Details: " + details;
    }
    logEntry += "\n--------------------\n";

    string encryptedEntry;
    try {
        encryptedEntry = encryption::encrypt(logEntry, masterPassword);
    } catch (const exception& e) {
        cerr << "Error: Failed to encrypt log entry: " << e.what() << endl;
        return;
    }

    ofstream file(activityLogFile, ios::binary | ios::app);
    if (!file.is_open()) {
        cerr << "Error: Could not open activity log file for writing.\n";
        return;
    }
    file.write(encryptedEntry.c_str(), encryptedEntry.size());
    file << "----ENTRY----";
    file.flush(); // Ensure data is written to disk
    if (file.fail()) {
        cerr << "Error: Failed to write to activity log file.\n";
    }
    file.close();
}

string Logger::getActivityLog() {
    if (masterPassword.empty()) return "Error: Master password not set.\n";

    ifstream file(activityLogFile, ios::binary);
    if (!file.is_open()) return "No logs found.\n";

    string encryptedData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    if (encryptedData.empty()) return "No logs found.\n";

    stringstream result;
    string delimiter = "----ENTRY----";

    // Check if the file contains the delimiter
    if (encryptedData.find(delimiter) == string::npos) {
        // Legacy file: try to decrypt as a single ciphertext
        try {
            string decryptedData = encryption::decrypt(encryptedData, masterPassword);
            if (!decryptedData.empty()) {
                result << decryptedData;
            } else {
                result << "Warning: Failed to decrypt legacy log (possibly corrupted or wrong password).\n";
            }
        } catch (const exception& e) {
            result << "Warning: Failed to decrypt legacy log: " << e.what() << "\n";
        }
    } else {
        // Modern file: split by delimiter
        size_t pos = 0;
        string segment;
        while ((pos = encryptedData.find(delimiter)) != string::npos) {
            segment = encryptedData.substr(0, pos);
            if (!segment.empty()) {
                try {
                    string decryptedSegment = encryption::decrypt(segment, masterPassword);
                    if (!decryptedSegment.empty()) {
                        result << decryptedSegment;
                    } else {
                        result << "Warning: Failed to decrypt a log entry (possibly corrupted or wrong password).\n";
                    }
                } catch (const exception& e) {
                    result << "Warning: Failed to decrypt a log entry: " << e.what() << "\n";
                }
            }
            encryptedData.erase(0, pos + delimiter.length());
        }
        // Handle the last segment
        if (!encryptedData.empty()) {
            try {
                string decryptedSegment = encryption::decrypt(encryptedData, masterPassword);
                if (!decryptedSegment.empty()) {
                    result << decryptedSegment;
                } else {
                    result << "Warning: Failed to decrypt a log entry (possibly corrupted or wrong password).\n";
                }
            } catch (const exception& e) {
                result << "Warning: Failed to decrypt a log entry: " << e.what() << "\n";
            }
        }
    }

    string finalResult = result.str();
    return finalResult.empty() ? "No logs found.\n" : finalResult;
}

void Logger::clearLog() {
    ofstream file(activityLogFile, ios::binary | ios::trunc);
    if (!file.is_open()) {
        cerr << "Error: Could not clear activity log file.\n";
    }
    file.close();
}