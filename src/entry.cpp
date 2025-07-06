#include "entry.h"
#include <sstream>

using namespace std;

Entry::Entry(const string& website, const string& username, 
             const string& password, const string& category)
    : website(website), username(username), password(password), category(category) {}

string Entry::getWebsite() const { return website; }
string Entry::getUsername() const { return username; }
string Entry::getPassword() const { return password; }
string Entry::getCategory() const { return category; }

string Entry::serialize() const {
    stringstream ss;
    ss << website << '\x1F' << username << '\x1F' << password << '\x1F' << category;
    return ss.str();
}

Entry Entry::deserialize(const string& data) {
    stringstream ss(data);
    string website, username, password, category;
    
    getline(ss, website, '\x1F');
    getline(ss, username, '\x1F');
    getline(ss, password, '\x1F');
    getline(ss, category, '\x1F');
    
    return Entry(website, username, password, category);
}

bool Entry::operator==(const Entry& other) const {
    return website == other.website && 
           username == other.username && 
           password == other.password && 
           category == other.category;
}