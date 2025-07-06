# VaultGuard++

VaultGuard++ is a secure, command-line password manager built in C++ for Windows. It offers robust encryption, two-factor authentication, clipboard copying, cloud backup to Google Drive, and configurable settings, making it a reliable solution for managing credentials securely.

## Features
- **Secure Authentication**: Master password with SHA-256 hashing, salted, and TOTP-based 2FA for password recovery.
- **Password Management**: Add, search, update, delete, and list entries; generate random passwords; copy credentials to clipboard.
- **Encryption**: Uses libsodium and OpenSSL to encrypt credentials and logs.
- **Cloud Backup**: Manual or automatic backup of encrypted files to Google Drive.
- **Configuration**: Adjustable session and input timeouts, auto-backup settings via `vaultguard.config`.
- **Logging**: Encrypted activity and security logs, viewable in the admin panel.
- **Session Management**: Automatic logout after inactivity with configurable timeout.

## Prerequisites
### C++ Dependencies
- **g++**: MinGW-w64 compiler
- **libsodium**: Encryption library
- **OpenSSL**: Hashing and encryption
- **MSYS2 MinGW64**: Build environment

### Python Dependencies (for Cloud Backup)
- **Google API Client Libraries**:

  pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

- **credentials.json**: From Google Cloud Console

## Installation
1. **Install Dependencies**:

   ### In MSYS2 MinGW64 terminal
   pacman -Syu
   
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-libsodium mingw-w64-x86_64-openssl mingw-w64-x86_64-make mingw-w64-x86_64-python
   
   pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client
   

3. **Set Up Google Drive API**:
   - Create a Google Cloud project at [console.cloud.google.com](https://console.cloud.google.com).
   - Enable Google Drive API, create OAuth 2.0 credentials, and download `credentials.json`.
   - Place `credentials.json` in the project root.

4. **Clone or Set Up Project**:
   - Ensure all source files are in the structure above.
   - Copy `backup.py` and `credentials.json` to the project root.

5. **Build the Project**:
   
   cd /path/to/VaultGuard
   
   mingw32-make clean
   
   mingw32-make

7. **Run the Application**:

   .\bin\vaultguard.exe
   

## Security Notes
- **Encryption**: All data is encrypted using libsodium and OpenSSL.
- **Lockout**: 3 failed logins trigger a 120-second lockout.
- **Clipboard**: Copied credentials may be vulnerable if the system is compromised.
- **Cloud Backup**: Files are encrypted before upload; protect `credentials.json`.


**Muhammad Adeel Haider - 241541**
BS Cyber Security, Air University
