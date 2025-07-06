#ifndef ENTRY_H
#define ENTRY_H

#include <string>

class Entry {
private:
    std::string website;
    std::string username;
    std::string password;
    std::string category;

public:
    Entry(const std::string& website, const std::string& username, 
          const std::string& password, const std::string& category);
    
    std::string getWebsite() const;
    std::string getUsername() const;
    std::string getPassword() const;
    std::string getCategory() const;

    std::string serialize() const;
    static Entry deserialize(const std::string& data);

    bool operator==(const Entry& other) const;
};

#endif // ENTRY_H