#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <cctype>

class AES {
public:
    // S-box for bit substitution
    static const uint8_t s_box[256];
    
    // Inverse S-box for decryption bit substitution
    static const uint8_t inv_s_box[256];
    
    // Round constants
    static const uint8_t Rcon[11];
    
    // Function to perform calculations over a 2^8 galois field
    static uint8_t xtime(uint8_t a) {
        return (a & 0x80) ? (((a << 1) ^ 0x1B) & 0xFF) : (a << 1);
    }
    
    // Function to substitute bytes during encryption
    static void byte_sub(uint8_t s[4][4]) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                s[i][j] = s_box[s[i][j]];
            }
        }
    }
    
    // Function to substitute bytes during decryption
    static void byte_sub_inv(uint8_t s[4][4]) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                s[i][j] = inv_s_box[s[i][j]];
            }
        }
    }
    
    // Shift rows operation
    static void shift_row(uint8_t s[4][4]) {
        uint8_t temp;
        
        // Row 1: shift left by 1
        temp = s[0][1];
        s[0][1] = s[1][1];
        s[1][1] = s[2][1];
        s[2][1] = s[3][1];
        s[3][1] = temp;
        
        // Row 2: shift left by 2
        temp = s[0][2];
        s[0][2] = s[2][2];
        s[2][2] = temp;
        temp = s[1][2];
        s[1][2] = s[3][2];
        s[3][2] = temp;
        
        // Row 3: shift left by 3 (or right by 1)
        temp = s[3][3];
        s[3][3] = s[2][3];
        s[2][3] = s[1][3];
        s[1][3] = s[0][3];
        s[0][3] = temp;
    }
    
    // Inverse shift rows operation
    static void shift_row_inv(uint8_t s[4][4]) {
        uint8_t temp;
        
        // Row 1: shift right by 1
        temp = s[3][1];
        s[3][1] = s[2][1];
        s[2][1] = s[1][1];
        s[1][1] = s[0][1];
        s[0][1] = temp;
        
        // Row 2: shift right by 2
        temp = s[0][2];
        s[0][2] = s[2][2];
        s[2][2] = temp;
        temp = s[1][2];
        s[1][2] = s[3][2];
        s[3][2] = temp;
        
        // Row 3: shift right by 3 (or left by 1)
        temp = s[0][3];
        s[0][3] = s[1][3];
        s[1][3] = s[2][3];
        s[2][3] = s[3][3];
        s[3][3] = temp;
    }
    
    // Adding round key
    static void round_key(uint8_t s[4][4], uint8_t k[4][4]) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                s[i][j] = s[i][j] ^ k[i][j];
            }
        }
    }
    
    // Individual mix column operation
    static void mix_col_individual(uint8_t x[4]) {
        uint8_t temp = x[0] ^ x[1] ^ x[2] ^ x[3];
        uint8_t u = x[0];
        x[0] ^= temp ^ xtime(x[0] ^ x[1]);
        x[1] ^= temp ^ xtime(x[1] ^ x[2]);
        x[2] ^= temp ^ xtime(x[2] ^ x[3]);
        x[3] ^= temp ^ xtime(x[3] ^ u);
    }
    
    // Mix columns operation
    static void mix_col(uint8_t s[4][4]) {
        for (int i = 0; i < 4; i++) {
            mix_col_individual(s[i]);
        }
    }
    
    // Inverse mix columns operation
    static void inv_mix_col(uint8_t s[4][4]) {
        for (int i = 0; i < 4; i++) {
            uint8_t u = xtime(xtime(s[i][0] ^ s[i][2]));
            uint8_t v = xtime(xtime(s[i][1] ^ s[i][3]));
            s[i][0] ^= u;
            s[i][1] ^= v;
            s[i][2] ^= u;
            s[i][3] ^= v;
            mix_col_individual(s[i]);
        }
    }
    
    // Convert 16-byte input to 4x4 state matrix
    static void input_to_state(const std::vector<uint8_t>& input, uint8_t s[4][4]) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                s[r][c] = input[r + 4 * c];
            }
        }
    }
    
    // Convert 4x4 state matrix to 16-byte output
    static std::vector<uint8_t> state_to_output(uint8_t s[4][4]) {
        std::vector<uint8_t> output(16);
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                output[c * 4 + r] = s[r][c];
            }
        }
        return output;
    }
    
    // Substitute word during key expansion
    static void sub_word(uint8_t word[4]) {
        for (int i = 0; i < 4; i++) {
            word[i] = s_box[word[i]];
        }
    }
    
    // Rotate word during key expansion
    static void rot_word(uint8_t word[4]) {
        uint8_t temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
    }
    
    // Validate hex string
    static bool is_valid_hex(const std::string& hex) {
        if (hex.empty() || hex.length() % 2 != 0) {
            return false;
        }
        
        for (char c : hex) {
            if (!std::isxdigit(c)) {
                return false;
            }
        }
        return true;
    }
    
    // Convert hex string to bytes
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    // Convert bytes to hex string
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    // Convert string to bytes (UTF-8)
    static std::vector<uint8_t> string_to_bytes(const std::string& str) {
        std::vector<uint8_t> bytes;
        for (char c : str) {
            bytes.push_back(static_cast<uint8_t>(c));
        }
        return bytes;
    }
    
    // Convert bytes to string
    static std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
        std::string str;
        for (uint8_t byte : bytes) {
            str.push_back(static_cast<char>(byte));
        }
        return str;
    }
    
    // Pad data to 16-byte blocks using PKCS7 padding
    static std::vector<uint8_t> pad_data(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> padded = data;
        size_t padding_length = 16 - (data.size() % 16);
        
        for (size_t i = 0; i < padding_length; i++) {
            padded.push_back(static_cast<uint8_t>(padding_length));
        }
        
        return padded;
    }
    
    // Remove PKCS7 padding
    static std::vector<uint8_t> unpad_data(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return data;
        }
        
        uint8_t padding_length = data.back();
        
        if (padding_length > 16 || padding_length > data.size()) {
            return data; // Invalid padding
        }
        
        // Verify padding
        for (size_t i = data.size() - padding_length; i < data.size(); i++) {
            if (data[i] != padding_length) {
                return data; // Invalid padding
            }
        }
        
        std::vector<uint8_t> unpadded(data.begin(), data.end() - padding_length);
        return unpadded;
    }

public:
    // Key expansion function
    static void key_expansion(const std::string& key_hex, uint8_t round_keys[11][4][4]) {
        std::vector<uint8_t> key_bytes = hex_to_bytes(key_hex);
        if (key_bytes.size() != 16) {
            throw std::invalid_argument("Key must be exactly 16 bytes (32 hex characters)");
        }
        
        // Key schedule as 44 words (4 bytes each)
        uint8_t key_schedule[44][4];
        
        // Initial 4 words from key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                key_schedule[i][j] = key_bytes[i * 4 + j];
            }
        }
        
        // Generate remaining 40 words
        for (int i = 4; i < 44; i++) {
            // Copy previous word
            for (int j = 0; j < 4; j++) {
                key_schedule[i][j] = key_schedule[i - 1][j];
            }
            
            if (i % 4 == 0) {
                rot_word(key_schedule[i]);
                sub_word(key_schedule[i]);
                key_schedule[i][0] ^= Rcon[i / 4];
            }
            
            // XOR with word 4 positions back
            for (int j = 0; j < 4; j++) {
                key_schedule[i][j] ^= key_schedule[i - 4][j];
            }
        }
        
        // Split into 11 round keys (4x4 matrices)
        for (int i = 0; i < 11; i++) {
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    round_keys[i][k][j] = key_schedule[4 * i + j][k];
                }
            }
        }
    }
    
    // AES encryption of a single block
    static std::vector<uint8_t> aes_encrypt_block(const std::vector<uint8_t>& block, 
                                                  uint8_t round_keys[11][4][4]) {
        if (block.size() != 16) {
            throw std::invalid_argument("Block must be exactly 16 bytes");
        }
        
        uint8_t state[4][4];
        input_to_state(block, state);
        
        // Initial round
        round_key(state, round_keys[0]);
        
        // Main rounds
        for (int i = 1; i < 10; i++) {
            byte_sub(state);
            shift_row(state);
            mix_col(state);
            round_key(state, round_keys[i]);
        }
        
        // Final round
        byte_sub(state);
        shift_row(state);
        round_key(state, round_keys[10]);
        
        return state_to_output(state);
    }
    
    // AES decryption of a single block
    static std::vector<uint8_t> aes_decrypt_block(const std::vector<uint8_t>& block, 
                                                  uint8_t round_keys[11][4][4]) {
        if (block.size() != 16) {
            throw std::invalid_argument("Block must be exactly 16 bytes");
        }
        
        uint8_t state[4][4];
        input_to_state(block, state);
        
        // Initial round (uses last round key)
        round_key(state, round_keys[10]);
        
        // Middle rounds (in reverse order)
        for (int i = 9; i > 0; i--) {
            shift_row_inv(state);
            byte_sub_inv(state);
            round_key(state, round_keys[i]);
            inv_mix_col(state);
        }
        
        // Final round (no MixColumns)
        shift_row_inv(state);
        byte_sub_inv(state);
        round_key(state, round_keys[0]);
        
        return state_to_output(state);
    }
    
    // Encrypt multiple blocks (ECB mode)
    static std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& data, 
                                           const std::string& key_hex) {
        uint8_t round_keys[11][4][4];
        key_expansion(key_hex, round_keys);
        
        std::vector<uint8_t> padded_data = pad_data(data);
        std::vector<uint8_t> encrypted_data;
        
        for (size_t i = 0; i < padded_data.size(); i += 16) {
            std::vector<uint8_t> block(padded_data.begin() + i, padded_data.begin() + i + 16);
            std::vector<uint8_t> encrypted_block = aes_encrypt_block(block, round_keys);
            encrypted_data.insert(encrypted_data.end(), encrypted_block.begin(), encrypted_block.end());
        }
        
        return encrypted_data;
    }
    
    // Decrypt multiple blocks (ECB mode)
    static std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& encrypted_data, 
                                           const std::string& key_hex) {
        if (encrypted_data.size() % 16 != 0) {
            throw std::invalid_argument("Encrypted data size must be multiple of 16 bytes");
        }
        
        uint8_t round_keys[11][4][4];
        key_expansion(key_hex, round_keys);
        
        std::vector<uint8_t> decrypted_data;
        
        for (size_t i = 0; i < encrypted_data.size(); i += 16) {
            std::vector<uint8_t> block(encrypted_data.begin() + i, encrypted_data.begin() + i + 16);
            std::vector<uint8_t> decrypted_block = aes_decrypt_block(block, round_keys);
            decrypted_data.insert(decrypted_data.end(), decrypted_block.begin(), decrypted_block.end());
        }
        
        return unpad_data(decrypted_data);
    }
    
    // Encrypt string data
    static std::string encrypt_string(const std::string& plaintext, const std::string& key_hex) {
        std::vector<uint8_t> data = string_to_bytes(plaintext);
        std::vector<uint8_t> encrypted = aes_encrypt(data, key_hex);
        return bytes_to_hex(encrypted);
    }
    
    // Decrypt string data
    static std::string decrypt_string(const std::string& encrypted_hex, const std::string& key_hex) {
        std::vector<uint8_t> encrypted = hex_to_bytes(encrypted_hex);
        std::vector<uint8_t> decrypted = aes_decrypt(encrypted, key_hex);
        return bytes_to_string(decrypted);
    }
    
    // Validate inputs
    static bool validate_inputs(const std::string& key_hex, const std::string& data_hex = "") {
        if (!is_valid_hex(key_hex) || key_hex.length() != 32) {
            std::cout << "Error: Key must be exactly 32 hex characters (16 bytes)" << std::endl;
            return false;
        }
        
        if (!data_hex.empty() && !is_valid_hex(data_hex)) {
            std::cout << "Error: Data must be valid hex characters" << std::endl;
            return false;
        }
        
        return true;
    }
};

// S-box definition
const uint8_t AES::s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

// Inverse S-box definition
const uint8_t AES::inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

// Round constants
const uint8_t AES::Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Helper functions for the interactive menu
void print_menu() {
    std::cout << "\n=== AES-128 Encryption/Decryption Tool ===" << std::endl;
    std::cout << "1. Encrypt text" << std::endl;
    std::cout << "2. Decrypt text" << std::endl;
    std::cout << "3. Encrypt hex data" << std::endl;
    std::cout << "4. Decrypt hex data" << std::endl;
    std::cout << "5. Test with sample data" << std::endl;
    std::cout << "6. Generate random key" << std::endl;
    std::cout << "7. Exit";
std::cout << "7. Exit" << std::endl;
    std::cout << "Enter your choice: ";
}

std::string generate_random_key() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    std::string key;
    const char hex_chars[] = "0123456789ABCDEF";
    
    for (int i = 0; i < 32; i++) {
        key += hex_chars[std::rand() % 16];
    }
    
    return key;
}

void test_sample_data() {
    std::cout << "\n=== Testing with sample data ===" << std::endl;
    
    std::string key = "2B7E151628AED2A6ABF7158809CF4F3C";
    std::string plaintext = "Hello, AES World!";
    
    std::cout << "Key: " << key << std::endl;
    std::cout << "Original text: " << plaintext << std::endl;
    
    try {
        std::string encrypted = AES::encrypt_string(plaintext, key);
        std::cout << "Encrypted (hex): " << encrypted << std::endl;
        
        std::string decrypted = AES::decrypt_string(encrypted, key);
        std::cout << "Decrypted text: " << decrypted << std::endl;
        
        if (plaintext == decrypted) {
            std::cout << "✓ Test passed! Encryption and decryption successful." << std::endl;
        } else {
            std::cout << "✗ Test failed! Decryption doesn't match original." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void encrypt_text() {
    std::string plaintext, key;
    
    std::cout << "\n=== Text Encryption ===" << std::endl;
    std::cout << "Enter text to encrypt: ";
    std::cin.ignore();
    std::getline(std::cin, plaintext);
    
    std::cout << "Enter 128-bit key (32 hex characters): ";
    std::cin >> key;
    
    if (!AES::validate_inputs(key)) {
        return;
    }
    
    try {
        std::string encrypted = AES::encrypt_string(plaintext, key);
        std::cout << "Encrypted (hex): " << encrypted << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void decrypt_text() {
    std::string encrypted_hex, key;
    
    std::cout << "\n=== Text Decryption ===" << std::endl;
    std::cout << "Enter encrypted hex data: ";
    std::cin >> encrypted_hex;
    
    std::cout << "Enter 128-bit key (32 hex characters): ";
    std::cin >> key;
    
    if (!AES::validate_inputs(key, encrypted_hex)) {
        return;
    }
    
    try {
        std::string decrypted = AES::decrypt_string(encrypted_hex, key);
        std::cout << "Decrypted text: " << decrypted << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void encrypt_hex_data() {
    std::string data_hex, key;
    
    std::cout << "\n=== Hex Data Encryption ===" << std::endl;
    std::cout << "Enter hex data to encrypt: ";
    std::cin >> data_hex;
    
    std::cout << "Enter 128-bit key (32 hex characters): ";
    std::cin >> key;
    
    if (!AES::validate_inputs(key, data_hex)) {
        return;
    }
    
    try {
        std::vector<uint8_t> data = AES::hex_to_bytes(data_hex);
        std::vector<uint8_t> encrypted = AES::aes_encrypt(data, key);
        std::string encrypted_hex = AES::bytes_to_hex(encrypted);
        std::cout << "Encrypted hex: " << encrypted_hex << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void decrypt_hex_data() {
    std::string encrypted_hex, key;
    
    std::cout << "\n=== Hex Data Decryption ===" << std::endl;
    std::cout << "Enter encrypted hex data: ";
    std::cin >> encrypted_hex;
    
    std::cout << "Enter 128-bit key (32 hex characters): ";
    std::cin >> key;
    
    if (!AES::validate_inputs(key, encrypted_hex)) {
        return;
    }
    
    try {
        std::vector<uint8_t> encrypted = AES::hex_to_bytes(encrypted_hex);
        std::vector<uint8_t> decrypted = AES::aes_decrypt(encrypted, key);
        std::string decrypted_hex = AES::bytes_to_hex(decrypted);
        std::cout << "Decrypted hex: " << decrypted_hex << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "AES-128 Implementation in C++" << std::endl;
    std::cout << "Educational purposes only" << std::endl;
    
    int choice;
    
    while (true) {
        print_menu();
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                encrypt_text();
                break;
            case 2:
                decrypt_text();
                break;
            case 3:
                encrypt_hex_data();
                break;
            case 4:
                decrypt_hex_data();
                break;
            case 5:
                test_sample_data();
                break;
            case 6:
                std::cout << "Generated random key: " << generate_random_key() << std::endl;
                break;
            case 7:
                std::cout << "Goodbye!" << std::endl;
                return 0;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
    }
    
    return 0;
}