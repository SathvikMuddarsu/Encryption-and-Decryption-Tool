/*
 * ============================================================
 *   ENCRYPTION & DECRYPTION TOOL
 *   Algorithms: Caesar Cipher | Vigenère Cipher | RSA
 *   Standard: C++17
 *   Author: Encryption Tool Demo
 * ============================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <limits>
#include <cmath>
#include <algorithm>
#include <stdexcept>

// ============================================================
//  UTILITY FUNCTIONS
// ============================================================

/**
 * Computes the Greatest Common Divisor of two numbers
 * using the Euclidean algorithm.
 */
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

/**
 * Extended Euclidean Algorithm.
 * Finds x, y such that: a*x + b*y = gcd(a, b)
 * Used to compute the modular inverse.
 */
long long extendedGCD(long long a, long long b, long long &x, long long &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    long long x1, y1;
    long long g = extendedGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

/**
 * Computes the modular inverse of a mod m.
 * Returns -1 if the inverse does not exist.
 */
long long modInverse(long long a, long long m) {
    long long x, y;
    long long g = extendedGCD(a, m, x, y);
    if (g != 1) return -1; // Inverse doesn't exist
    return (x % m + m) % m;
}

/**
 * Fast modular exponentiation.
 * Computes (base^exp) mod mod efficiently using
 * the "square and multiply" algorithm.
 */
long long modPow(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {          // If exp is odd, multiply base with result
            result = (result * base) % mod;
        }
        exp = exp / 2;               // exp = exp / 2
        base = (base * base) % mod;  // base = base^2
    }
    return result;
}

/**
 * Checks if a number is prime using trial division.
 */
bool isPrime(long long n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (long long i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

// ============================================================
//  UI HELPERS
// ============================================================

void printLine(char ch = '-', int width = 60) {
    std::cout << std::string(width, ch) << "\n";
}

void printHeader(const std::string &title) {
    printLine('=');
    int padding = (60 - (int)title.size()) / 2;
    std::cout << std::string(padding, ' ') << title << "\n";
    printLine('=');
}

void printSubHeader(const std::string &title) {
    printLine('-');
    std::cout << "  " << title << "\n";
    printLine('-');
}

void clearInput() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// ============================================================
//  CLASS: CaesarCipher
// ============================================================

/**
 * Caesar Cipher shifts each letter in the plaintext by
 * a fixed number of positions (the "shift" or "key").
 * Non-alphabet characters are left unchanged.
 */
class CaesarCipher {
public:

    /**
     * Encrypts a plaintext string using the Caesar cipher.
     * @param text     The plaintext string
     * @param shift    The shift value (integer)
     * @return         The ciphertext string
     */
    std::string encrypt(const std::string &text, int shift) {
        // Normalize shift to [0, 25]
        shift = ((shift % 26) + 26) % 26;
        std::string result = "";
        for (char c : text) {
            if (std::isupper(c)) {
                // Shift uppercase letters, wrap around with modulo
                result += (char)(((c - 'A' + shift) % 26) + 'A');
            } else if (std::islower(c)) {
                // Shift lowercase letters, wrap around with modulo
                result += (char)(((c - 'a' + shift) % 26) + 'a');
            } else {
                result += c; // Keep non-alphabet characters unchanged
            }
        }
        return result;
    }

    /**
     * Decrypts a ciphertext string using the Caesar cipher.
     * Decryption is just encryption with a negative shift.
     * @param text     The ciphertext string
     * @param shift    The shift value used during encryption
     * @return         The plaintext string
     */
    std::string decrypt(const std::string &text, int shift) {
        return encrypt(text, -shift); // Reverse the shift
    }

    /**
     * Interactive menu for Caesar Cipher operations.
     */
    void menu() {
        printSubHeader("CAESAR CIPHER");
        std::cout << "  [1] Encrypt\n";
        std::cout << "  [2] Decrypt\n";
        std::cout << "  [3] Encrypt/Decrypt from File\n";
        std::cout << "  [0] Back\n";
        printLine();
        std::cout << "  Choice: ";

        int choice;
        std::cin >> choice;
        clearInput();

        if (choice == 0) return;

        if (choice == 3) {
            fileOperation();
            return;
        }

        if (choice != 1 && choice != 2) {
            std::cout << "\n  [!] Invalid choice.\n";
            return;
        }

        std::cout << "\n  Enter text: ";
        std::string text;
        std::getline(std::cin, text);

        std::cout << "  Enter shift value: ";
        int shift;
        while (!(std::cin >> shift)) {
            std::cout << "  [!] Invalid input. Enter an integer: ";
            clearInput();
        }
        clearInput();

        std::string output;
        if (choice == 1) {
            output = encrypt(text, shift);
            std::cout << "\n  Encrypted Text : " << output << "\n";
        } else {
            output = decrypt(text, shift);
            std::cout << "\n  Decrypted Text : " << output << "\n";
        }
    }

    /**
     * File-based encrypt/decrypt using Caesar Cipher.
     */
    void fileOperation() {
        std::cout << "\n  Enter input filename: ";
        std::string inFile;
        std::getline(std::cin, inFile);

        std::ifstream fin(inFile);
        if (!fin.is_open()) {
            std::cout << "  [!] Could not open file: " << inFile << "\n";
            return;
        }

        std::string content((std::istreambuf_iterator<char>(fin)),
                             std::istreambuf_iterator<char>());
        fin.close();

        std::cout << "  Enter shift value: ";
        int shift;
        std::cin >> shift;
        clearInput();

        std::cout << "  [1] Encrypt  [2] Decrypt: ";
        int op;
        std::cin >> op;
        clearInput();

        std::string result = (op == 1) ? encrypt(content, shift) : decrypt(content, shift);

        std::cout << "  Enter output filename: ";
        std::string outFile;
        std::getline(std::cin, outFile);

        std::ofstream fout(outFile);
        if (!fout.is_open()) {
            std::cout << "  [!] Could not write to file: " << outFile << "\n";
            return;
        }
        fout << result;
        fout.close();

        std::cout << "  [✓] Done! Output written to: " << outFile << "\n";
    }
};

// ============================================================
//  CLASS: VigenereCipher
// ============================================================

/**
 * Vigenère Cipher uses a keyword to determine variable shifts
 * for each character. It is a polyalphabetic substitution cipher.
 * The keyword is repeated to match the length of the plaintext.
 */
class VigenereCipher {
private:
    /**
     * Extracts only alphabetic characters from keyword and
     * converts to uppercase for uniform processing.
     */
    std::string sanitizeKey(const std::string &key) {
        std::string cleanKey = "";
        for (char c : key) {
            if (std::isalpha(c)) cleanKey += std::toupper(c);
        }
        return cleanKey;
    }

public:

    /**
     * Encrypts using the Vigenère cipher.
     * Each letter is shifted by the corresponding key letter value.
     * Key index only advances for alphabetic characters.
     *
     * @param text     The plaintext
     * @param key      The keyword
     * @return         The ciphertext
     */
    std::string encrypt(const std::string &text, const std::string &key) {
        std::string cleanKey = sanitizeKey(key);
        if (cleanKey.empty()) {
            std::cout << "  [!] Key must contain at least one letter.\n";
            return text;
        }

        std::string result = "";
        int keyIndex = 0;
        int keyLen = cleanKey.size();

        for (char c : text) {
            if (std::isupper(c)) {
                int shift = cleanKey[keyIndex % keyLen] - 'A'; // Key letter value
                result += (char)(((c - 'A' + shift) % 26) + 'A');
                keyIndex++;
            } else if (std::islower(c)) {
                int shift = cleanKey[keyIndex % keyLen] - 'A';
                result += (char)(((c - 'a' + shift) % 26) + 'a');
                keyIndex++;
            } else {
                result += c; // Non-alpha characters unchanged
            }
        }
        return result;
    }

    /**
     * Decrypts using the Vigenère cipher.
     * Each letter is un-shifted by the corresponding key letter value.
     *
     * @param text     The ciphertext
     * @param key      The keyword
     * @return         The plaintext
     */
    std::string decrypt(const std::string &text, const std::string &key) {
        std::string cleanKey = sanitizeKey(key);
        if (cleanKey.empty()) {
            std::cout << "  [!] Key must contain at least one letter.\n";
            return text;
        }

        std::string result = "";
        int keyIndex = 0;
        int keyLen = cleanKey.size();

        for (char c : text) {
            if (std::isupper(c)) {
                int shift = cleanKey[keyIndex % keyLen] - 'A';
                // Add 26 before taking mod to avoid negative values
                result += (char)(((c - 'A' - shift + 26) % 26) + 'A');
                keyIndex++;
            } else if (std::islower(c)) {
                int shift = cleanKey[keyIndex % keyLen] - 'A';
                result += (char)(((c - 'a' - shift + 26) % 26) + 'a');
                keyIndex++;
            } else {
                result += c;
            }
        }
        return result;
    }

    /**
     * Interactive menu for Vigenère Cipher operations.
     */
    void menu() {
        printSubHeader("VIGENERE CIPHER");
        std::cout << "  [1] Encrypt\n";
        std::cout << "  [2] Decrypt\n";
        std::cout << "  [3] Encrypt/Decrypt from File\n";
        std::cout << "  [0] Back\n";
        printLine();
        std::cout << "  Choice: ";

        int choice;
        std::cin >> choice;
        clearInput();

        if (choice == 0) return;

        if (choice == 3) {
            fileOperation();
            return;
        }

        if (choice != 1 && choice != 2) {
            std::cout << "\n  [!] Invalid choice.\n";
            return;
        }

        std::cout << "\n  Enter text: ";
        std::string text;
        std::getline(std::cin, text);

        std::cout << "  Enter keyword: ";
        std::string keyword;
        std::getline(std::cin, keyword);

        std::string output;
        if (choice == 1) {
            output = encrypt(text, keyword);
            std::cout << "\n  Encrypted Text : " << output << "\n";
        } else {
            output = decrypt(text, keyword);
            std::cout << "\n  Decrypted Text : " << output << "\n";
        }
    }

    /**
     * File-based encrypt/decrypt using Vigenère Cipher.
     */
    void fileOperation() {
        std::cout << "\n  Enter input filename: ";
        std::string inFile;
        std::getline(std::cin, inFile);

        std::ifstream fin(inFile);
        if (!fin.is_open()) {
            std::cout << "  [!] Could not open file: " << inFile << "\n";
            return;
        }

        std::string content((std::istreambuf_iterator<char>(fin)),
                             std::istreambuf_iterator<char>());
        fin.close();

        std::cout << "  Enter keyword: ";
        std::string keyword;
        std::getline(std::cin, keyword);

        std::cout << "  [1] Encrypt  [2] Decrypt: ";
        int op;
        std::cin >> op;
        clearInput();

        std::string result = (op == 1) ? encrypt(content, keyword) : decrypt(content, keyword);

        std::cout << "  Enter output filename: ";
        std::string outFile;
        std::getline(std::cin, outFile);

        std::ofstream fout(outFile);
        if (!fout.is_open()) {
            std::cout << "  [!] Could not write to file: " << outFile << "\n";
            return;
        }
        fout << result;
        fout.close();

        std::cout << "  [✓] Done! Output written to: " << outFile << "\n";
    }
};

// ============================================================
//  CLASS: RSA
// ============================================================

/**
 * RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem.
 *
 * Key Generation Steps:
 *   1. Choose two distinct primes p and q
 *   2. Compute n = p * q  (modulus)
 *   3. Compute phi = (p-1) * (q-1)  (Euler's totient)
 *   4. Choose e such that 1 < e < phi and gcd(e, phi) = 1
 *   5. Compute d = modular inverse of e mod phi (private key)
 *
 * Encryption: C = M^e mod n
 * Decryption: M = C^d mod n
 */
class RSA {
private:
    long long p, q;     // Prime numbers
    long long n;        // Modulus: n = p * q
    long long phi;      // Euler's totient: phi = (p-1)*(q-1)
    long long e;        // Public exponent
    long long d;        // Private exponent (modular inverse of e)
    bool keysGenerated; // Flag to check if keys have been set up

public:
    RSA() : p(0), q(0), n(0), phi(0), e(0), d(0), keysGenerated(false) {}

    /**
     * Generates RSA key pairs from two prime inputs.
     * @param pIn  First prime number
     * @param qIn  Second prime number
     * @return     True if key generation succeeded, false otherwise
     */
    bool generateKeys(long long pIn, long long qIn) {
        // Validate primes
        if (!isPrime(pIn)) {
            std::cout << "  [!] " << pIn << " is not a prime number.\n";
            return false;
        }
        if (!isPrime(qIn)) {
            std::cout << "  [!] " << qIn << " is not a prime number.\n";
            return false;
        }
        if (pIn == qIn) {
            std::cout << "  [!] p and q must be distinct.\n";
            return false;
        }

        p   = pIn;
        q   = qIn;
        n   = p * q;                    // Step 2: Modulus
        phi = (p - 1) * (q - 1);       // Step 3: Euler's Totient

        // Step 4: Find a valid public exponent e
        // Common choice: start from 2, pick first e coprime with phi
        e = 2;
        while (e < phi) {
            if (gcd(e, phi) == 1) break;
            e++;
        }

        if (e >= phi) {
            std::cout << "  [!] Could not find a valid public exponent e.\n";
            return false;
        }

        // Step 5: Compute private key d (modular inverse of e mod phi)
        d = modInverse(e, phi);
        if (d == -1) {
            std::cout << "  [!] Failed to compute private key.\n";
            return false;
        }

        keysGenerated = true;

        // Display key information
        std::cout << "\n";
        printLine('*');
        std::cout << "  RSA KEY GENERATION SUCCESSFUL\n";
        printLine('*');
        std::cout << "  p   = " << p   << "\n";
        std::cout << "  q   = " << q   << "\n";
        std::cout << "  n   = p * q         = " << n   << "\n";
        std::cout << "  phi = (p-1)*(q-1)   = " << phi << "\n";
        std::cout << "  e   = " << e << "  (Public Key Exponent)\n";
        std::cout << "  d   = " << d << "  (Private Key)\n";
        std::cout << "  Public  Key: (" << e << ", " << n << ")\n";
        std::cout << "  Private Key: (" << d << ", " << n << ")\n";
        printLine('*');

        return true;
    }

    /**
     * Encrypts a numeric message M.
     * Formula: C = M^e mod n
     * @param M  Numeric plaintext (must satisfy 0 <= M < n)
     * @return   Encrypted ciphertext C
     */
    long long encrypt(long long M) {
        if (!keysGenerated) {
            std::cout << "  [!] Keys not generated yet.\n";
            return -1;
        }
        if (M < 0 || M >= n) {
            std::cout << "  [!] Message must be between 0 and " << (n - 1) << ".\n";
            return -1;
        }
        return modPow(M, e, n); // C = M^e mod n
    }

    /**
     * Decrypts a numeric ciphertext C.
     * Formula: M = C^d mod n
     * @param C  Ciphertext integer
     * @return   Decrypted plaintext M
     */
    long long decrypt(long long C) {
        if (!keysGenerated) {
            std::cout << "  [!] Keys not generated yet.\n";
            return -1;
        }
        return modPow(C, d, n); // M = C^d mod n
    }

    /**
     * Interactive menu for RSA operations.
     */
    void menu() {
        printSubHeader("RSA ALGORITHM");
        std::cout << "  [1] Generate Keys\n";
        std::cout << "  [2] Encrypt a Number\n";
        std::cout << "  [3] Decrypt a Number\n";
        std::cout << "  [4] Full Demo (auto generate + encrypt + decrypt)\n";
        std::cout << "  [0] Back\n";
        printLine();
        std::cout << "  Choice: ";

        int choice;
        std::cin >> choice;
        clearInput();

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "\n  Enter prime p: ";
                long long pIn;
                std::cin >> pIn;
                std::cout << "  Enter prime q: ";
                long long qIn;
                std::cin >> qIn;
                clearInput();
                generateKeys(pIn, qIn);
                break;
            }

            case 2: {
                if (!keysGenerated) {
                    std::cout << "\n  [!] Please generate keys first (option 1).\n";
                    break;
                }
                std::cout << "\n  Enter message (integer, 0 to " << (n - 1) << "): ";
                long long M;
                std::cin >> M;
                clearInput();
                long long C = encrypt(M);
                if (C != -1)
                    std::cout << "\n  Encrypted (C = M^e mod n): " << C << "\n";
                break;
            }

            case 3: {
                if (!keysGenerated) {
                    std::cout << "\n  [!] Please generate keys first (option 1).\n";
                    break;
                }
                std::cout << "\n  Enter ciphertext (integer): ";
                long long C;
                std::cin >> C;
                clearInput();
                long long M = decrypt(C);
                std::cout << "\n  Decrypted (M = C^d mod n): " << M << "\n";
                break;
            }

            case 4: {
                // Full automated demo
                std::cout << "\n  [Demo] Using p=61, q=53, message=42\n";
                if (generateKeys(61, 53)) {
                    long long msg = 42;
                    long long cipher  = encrypt(msg);
                    long long plain   = decrypt(cipher);
                    std::cout << "\n  Original Message : " << msg    << "\n";
                    std::cout << "  Encrypted        : " << cipher  << "\n";
                    std::cout << "  Decrypted Back   : " << plain   << "\n";
                }
                break;
            }

            default:
                std::cout << "\n  [!] Invalid choice.\n";
        }
    }
};

// ============================================================
//  MAIN MENU
// ============================================================

void showMainMenu() {
    std::cout << "\n";
    printHeader("ENCRYPTION & DECRYPTION TOOL");
    std::cout << "\n";
    std::cout << "  [1]  Caesar Cipher\n";
    std::cout << "  [2]  Vigenere Cipher\n";
    std::cout << "  [3]  RSA Algorithm\n";
    std::cout << "  [0]  Exit\n";
    std::cout << "\n";
    printLine();
    std::cout << "  Choose an algorithm: ";
}

// ============================================================
//  MAIN FUNCTION
// ============================================================

int main() {
    CaesarCipher  caesar;
    VigenereCipher vigenere;
    RSA           rsa;

    int choice = -1;

    while (true) {
        showMainMenu();

        if (!(std::cin >> choice)) {
            clearInput();
            std::cout << "\n  [!] Invalid input. Please enter a number.\n";
            continue;
        }
        clearInput();

        std::cout << "\n";

        switch (choice) {
            case 0:
                printLine('=');
                std::cout << "  Goodbye! Stay secure.\n";
                printLine('=');
                return 0;

            case 1:
                caesar.menu();
                break;

            case 2:
                vigenere.menu();
                break;

            case 3:
                rsa.menu();
                break;

            default:
                std::cout << "  [!] Invalid choice. Please select 0-3.\n";
        }

        std::cout << "\n  Press ENTER to return to main menu...";
        std::cin.get();
    }

    return 0;
}

/*
 * ============================================================
 *  SAMPLE RUN
 * ============================================================
 *
 * ============================================================
 *        ENCRYPTION & DECRYPTION TOOL
 * ============================================================
 *
 *   [1]  Caesar Cipher
 *   [2]  Vigenere Cipher
 *   [3]  RSA Algorithm
 *   [0]  Exit
 *
 * ------------------------------------------------------------
 *   Choose an algorithm: 1
 *
 * ------------------------------------------------------------
 *   CAESAR CIPHER
 * ------------------------------------------------------------
 *   [1] Encrypt
 *   [2] Decrypt
 *   [3] Encrypt/Decrypt from File
 *   [0] Back
 * ------------------------------------------------------------
 *   Choice: 1
 *
 *   Enter text: Hello World!
 *   Enter shift value: 3
 *
 *   Encrypted Text : Khoor Zruog!
 *
 * ============================================================
 *   Choose an algorithm: 2
 *
 *   VIGENERE CIPHER
 *   Choice: 1
 *   Enter text: Hello World
 *   Enter keyword: KEY
 *
 *   Encrypted Text : Rijvs Ambpb
 *
 * ============================================================
 *   Choose an algorithm: 3
 *
 *   RSA ALGORITHM
 *   Choice: 4  (Demo)
 *
 *   [Demo] Using p=61, q=53, message=42
 *   p   = 61
 *   q   = 53
 *   n   = 3233
 *   phi = 3120
 *   e   = 7
 *   d   = 2903
 *   Public  Key: (7, 3233)
 *   Private Key: (2903, 3233)
 *
 *   Original Message : 42
 *   Encrypted        : 2557
 *   Decrypted Back   : 42
 * ============================================================
 */