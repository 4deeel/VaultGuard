#ifndef GENERATOR_H
#define GENERATOR_H

#include <string>

class PasswordGenerator {
private:
    bool getUserChoice(const std::string& prompt) const;

public:
    PasswordGenerator() = default;
    std::string generatePassword();
};

#endif // GENERATOR_H