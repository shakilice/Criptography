#include <iostream>
#include <cstring>

#define BLOCK_SIZE 4

using namespace std;

// Encrypt a block using a simple shift cipher
void encrypt_block(unsigned char* block, int key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = (block[i] + key) % 256;
    }
}

// Decrypt a block using a simple shift cipher
void decrypt_block(unsigned char* block, int key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = (block[i] - key + 256) % 256;
    }
}

// XOR two byte blocks
void xor_bytes(unsigned char* out, const unsigned char* a, const unsigned char* b) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// Pad data to multiple of BLOCK_SIZE with 0x00
int pad(const unsigned char* input, int len, unsigned char* padded) {
    int padding_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    int total_len = len + padding_len;
    for (int i = 0; i < len; i++) padded[i] = input[i];
    for (int i = len; i < total_len; i++) padded[i] = 0x00;
    return total_len;
}

// Remove trailing 0x00
int unpad(unsigned char* data, int len) {
    while (len > 0 && data[len - 1] == 0x00) len--;
    return len;
}

// ECB Mode
int encrypt_ecb(const unsigned char* plaintext, int len, int key, unsigned char* ciphertext) {
    int padded_len = pad(plaintext, len, ciphertext);
    for (int i = 0; i < padded_len; i += BLOCK_SIZE)
        encrypt_block(ciphertext + i, key);
    return padded_len;
}

int decrypt_ecb(const unsigned char* ciphertext, int len, int key, unsigned char* plaintext) {
    memcpy(plaintext, ciphertext, len);
    for (int i = 0; i < len; i += BLOCK_SIZE)
        decrypt_block(plaintext + i, key);
    return unpad(plaintext, len);
}

// CBC Mode
int encrypt_cbc(const unsigned char* plaintext, int len, int key, const unsigned char* iv, unsigned char* ciphertext) {
    unsigned char padded[256];
    int padded_len = pad(plaintext, len, padded);
    unsigned char prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (int i = 0; i < padded_len; i += BLOCK_SIZE) {
        unsigned char block[BLOCK_SIZE];
        xor_bytes(block, padded + i, prev);
        encrypt_block(block, key);
        memcpy(ciphertext + i, block, BLOCK_SIZE);
        memcpy(prev, block, BLOCK_SIZE);
    }
    return padded_len;
}

int decrypt_cbc(const unsigned char* ciphertext, int len, int key, const unsigned char* iv, unsigned char* plaintext) {
    unsigned char prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (int i = 0; i < len; i += BLOCK_SIZE) {
        unsigned char block[BLOCK_SIZE];
        memcpy(block, ciphertext + i, BLOCK_SIZE);
        decrypt_block(block, key);
        xor_bytes(plaintext + i, block, prev);
        memcpy(prev, ciphertext + i, BLOCK_SIZE);
    }
    return unpad(plaintext, len);
}

// CFB Mode
int encrypt_cfb(const unsigned char* plaintext, int len, int key, const unsigned char* iv, unsigned char* ciphertext) {
    unsigned char padded[256];
    int padded_len = pad(plaintext, len, padded);
    unsigned char feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    for (int i = 0; i < padded_len; i += BLOCK_SIZE) {
        unsigned char temp[BLOCK_SIZE];
        memcpy(temp, feedback, BLOCK_SIZE);
        encrypt_block(temp, key);
        xor_bytes(ciphertext + i, padded + i, temp);
        memcpy(feedback, ciphertext + i, BLOCK_SIZE);
    }
    return padded_len;
}

int decrypt_cfb(const unsigned char* ciphertext, int len, int key, const unsigned char* iv, unsigned char* plaintext) {
    unsigned char feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    for (int i = 0; i < len; i += BLOCK_SIZE) {
        unsigned char temp[BLOCK_SIZE];
        memcpy(temp, feedback, BLOCK_SIZE);
        encrypt_block(temp, key);
        xor_bytes(plaintext + i, ciphertext + i, temp);
        memcpy(feedback, ciphertext + i, BLOCK_SIZE);
    }
    return unpad(plaintext, len);
}

// OFB Mode
int encrypt_ofb(const unsigned char* plaintext, int len, int key, const unsigned char* iv, unsigned char* ciphertext) {
    unsigned char padded[256];
    int padded_len = pad(plaintext, len, padded);
    unsigned char feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    for (int i = 0; i < padded_len; i += BLOCK_SIZE) {
        encrypt_block(feedback, key);
        xor_bytes(ciphertext + i, padded + i, feedback);
    }
    return padded_len;
}

int decrypt_ofb(const unsigned char* ciphertext, int len, int key, const unsigned char* iv, unsigned char* plaintext) {
    unsigned char feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    for (int i = 0; i < len; i += BLOCK_SIZE) {
        encrypt_block(feedback, key);
        xor_bytes(plaintext + i, ciphertext + i, feedback);
    }
    return unpad(plaintext, len);
}

int main() {
    unsigned char message[] = "Hello Block Modes!";
    int message_len = strlen((char*)message);
    unsigned char iv[BLOCK_SIZE] = {1, 2, 3, 4};
    int key = 5;

    unsigned char encrypted[256], decrypted[256];
    int cipher_len, plain_len;

    cout << "Original: " << message << endl;

    cout << "\n--- ECB ---" << endl;
    cipher_len = encrypt_ecb(message, message_len, key, encrypted);
    plain_len = decrypt_ecb(encrypted, cipher_len, key, decrypted);
    decrypted[plain_len] = '\0';
    cout << "Decrypted: " << decrypted << endl;

    cout << "\n--- CBC ---" << endl;
    cipher_len = encrypt_cbc(message, message_len, key, iv, encrypted);
    plain_len = decrypt_cbc(encrypted, cipher_len, key, iv, decrypted);
    decrypted[plain_len] = '\0';
    cout << "Decrypted: " << decrypted << endl;

    cout << "\n--- CFB ---" << endl;
    cipher_len = encrypt_cfb(message, message_len, key, iv, encrypted);
    plain_len = decrypt_cfb(encrypted, cipher_len, key, iv, decrypted);
    decrypted[plain_len] = '\0';
    cout << "Decrypted: " << decrypted << endl;

    cout << "\n--- OFB ---" << endl;
    cipher_len = encrypt_ofb(message, message_len, key, iv, encrypted);
    plain_len = decrypt_ofb(encrypted, cipher_len, key, iv, decrypted);
    decrypted[plain_len] = '\0';
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}
