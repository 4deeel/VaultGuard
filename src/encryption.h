#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

namespace encryption {
    std::string encrypt(const std::string& plaintext, const std::string& masterPassword);
    std::string decrypt(const std::string& ciphertext, const std::string& masterPassword);
}

#endif // ENCRYPTION_H