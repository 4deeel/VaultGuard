#include "encryption.h"
#include <sodium.h>
#include <stdexcept>
#include <vector>

using namespace std;

namespace encryption {
    const size_t SALT_LENGTH = crypto_pwhash_SALTBYTES; // 16 bytes
    const size_t KEY_LENGTH = crypto_secretbox_KEYBYTES; // 32 bytes
    const size_t NONCE_LENGTH = crypto_secretbox_NONCEBYTES; // 24 bytes
    const size_t MAC_LENGTH = crypto_secretbox_MACBYTES; // 16 bytes

    // Initialize libsodium
    struct SodiumInit {
        SodiumInit() {
            if (::sodium_init() < 0) {
                throw runtime_error("Failed to initialize libsodium");
            }
        }
    };
    static SodiumInit sodium_init_instance;

    // Generate random bytes
    vector<unsigned char> generateRandomBytes(size_t length) {
        vector<unsigned char> bytes(length);
        randombytes_buf(bytes.data(), length);
        return bytes;
    }

    // Derive key from master password using Argon2
    vector<unsigned char> deriveKey(const string& password, const vector<unsigned char>& salt) {
        vector<unsigned char> key(KEY_LENGTH);
        if (crypto_pwhash(
                key.data(), KEY_LENGTH,
                password.c_str(), password.length(),
                salt.data(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_DEFAULT) != 0) {
            throw runtime_error("Key derivation failed");
        }
        return key;
    }

    string encrypt(const string& plaintext, const string& masterPassword) {
        if (plaintext.empty()) return "";
        if (masterPassword.empty()) throw runtime_error("Master password cannot be empty");

        // Generate salt and nonce
        vector<unsigned char> salt = generateRandomBytes(SALT_LENGTH);
        vector<unsigned char> nonce = generateRandomBytes(NONCE_LENGTH);
        vector<unsigned char> key = deriveKey(masterPassword, salt);

        // Prepare ciphertext buffer (plaintext + MAC)
        vector<unsigned char> ciphertext(plaintext.size() + MAC_LENGTH);

        // Encrypt
        if (crypto_secretbox_easy(
                ciphertext.data(),
                reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                plaintext.size(),
                nonce.data(),
                key.data()) != 0) {
            throw runtime_error("Encryption failed");
        }

        // Combine salt, nonce, and ciphertext
        string result;
        result.reserve(SALT_LENGTH + NONCE_LENGTH + ciphertext.size());
        result.append(reinterpret_cast<const char*>(salt.data()), SALT_LENGTH);
        result.append(reinterpret_cast<const char*>(nonce.data()), NONCE_LENGTH);
        result.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

        return result;
    }

    string decrypt(const string& ciphertext, const string& masterPassword) {
        if (ciphertext.empty()) return "";
        if (masterPassword.empty()) throw runtime_error("Master password cannot be empty");
        if (ciphertext.size() < SALT_LENGTH + NONCE_LENGTH + MAC_LENGTH) {
            return "";
        }

        // Extract salt, nonce, and ciphertext
        vector<unsigned char> salt(ciphertext.begin(), ciphertext.begin() + SALT_LENGTH);
        vector<unsigned char> nonce(ciphertext.begin() + SALT_LENGTH, 
                                  ciphertext.begin() + SALT_LENGTH + NONCE_LENGTH);
        vector<unsigned char> encrypted(ciphertext.begin() + SALT_LENGTH + NONCE_LENGTH, 
                                      ciphertext.end());

        // Derive key
        vector<unsigned char> key = deriveKey(masterPassword, salt);

        // Prepare plaintext buffer
        vector<unsigned char> plaintext(encrypted.size() - MAC_LENGTH);

        // Decrypt
        if (crypto_secretbox_open_easy(
                plaintext.data(),
                encrypted.data(),
                encrypted.size(),
                nonce.data(),
                key.data()) != 0) {
            return "";
        }

        return string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    }
}