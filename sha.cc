#include "sha.hh"

#include <cstring>
#include <string>
#include <iostream>
#include <iomanip>
#include <bitset>
#include <array>
#include <vector>
#include <sstream>

constexpr std::array<unsigned int, 64> sha256kConstants {
    { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }
};

constexpr std::array<unsigned int, 8> sha256hValues {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
};

constexpr std::array<unsigned int, 8> sha224hValues {
    { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 }
};

union word_t {
    word_t(unsigned int _word) : word{_word} {};

    unsigned int word;
    char bytes[4];
};

void printBytes(char* bytes, std::size_t size) {
    for(int i = 0; i < size; i++) {
        std::cout << std::bitset<8>(bytes[i]) << ' ';
    }
    std::cout << '\n';
}

void swapEndianWrite(char* dst, char* src, std::size_t size) {
    for(int i = 0; i < size; i++) {
        dst[i] = src[(size-1)-i];
    }
}

unsigned int rotateRight(unsigned int src, unsigned int count) {
    count %= 32;
    return (src << (32 - count)) | (src >> count);
}

unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}

unsigned int maj(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

unsigned int S0(unsigned int x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

unsigned int S1(unsigned int x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

unsigned int s0(unsigned int x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

unsigned int s1(unsigned int x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

void sha256Compression(std::array<unsigned int, 8>& registers, const std::array<unsigned int, 64>& mQueue) {
    unsigned int temp1, temp2;
    for(int j = 0; j < 64; j++) {
        temp1 = registers[7] + S1(registers[4]) + ch(registers[4], registers[5], registers[6]) + sha256kConstants[j] + mQueue[j];
        temp2 = S0(registers[0]) + maj(registers[0], registers[1], registers[2]);
        registers[7] = registers[6];
        registers[6] = registers[5];
        registers[5] = registers[4];
        registers[4] = registers[3] + temp1;
        registers[3] = registers[2];
        registers[2] = registers[1];
        registers[1] = registers[0];
        registers[0] = temp1 + temp2;
    }
}

std::string sha256(const std::vector<char>& message) {
    unsigned long mLength = message.size();
    unsigned long mLengthBits = mLength * 8;
    unsigned int padding = 512 - ((mLengthBits + 1 + 64) % 512);
    unsigned int hLength = ((mLengthBits) + 1 + 64 + padding) / 8;
    std::vector<word_t> hash(hLength / 4, 0);
    memset(hash.data(), 0, hLength);
    memcpy(hash.data(), message.data(), mLength);

    hash[0].bytes[mLength] = 0b10000000;
    swapEndianWrite(&hash[0].bytes[hLength - 8], (char*)&mLengthBits, 8);

    std::array<unsigned int, 64> mQueue;
    std::array<unsigned int, 8> hValues{sha256hValues};
    for(int i = 0; i < hash.size() / 16; i++) {
        for(int j = 0; j < 16; j++) {
            swapEndianWrite((char*)&mQueue[j], (char*)&hash[i * 16 + j].word, 4);
        }

        for(int j = 16; j < 64; j++) {
            mQueue[j] = s1(mQueue[j-2]) + mQueue[j-7] + s0(mQueue[j-15]) + mQueue[j-16];
        }

        std::array<unsigned int, 8> registers{hValues};
        sha256Compression(registers, mQueue);

        for(int j = 0; j < 8; j++) {
            hValues[j] = registers[j] + hValues[j];
        }
    }

    std::stringstream ss;
    for(auto h : hValues) {
        ss << std::hex << std::setw(8) << std::setfill('0') << h;
    }

    return ss.str();
}

std::string sha224(const std::vector<char>& message) {
    unsigned long mLength = message.size();
    unsigned long mLengthBits = mLength * 8;
    unsigned int padding = 512 - ((mLengthBits + 1 + 64) % 512);
    unsigned int hLength = ((mLengthBits) + 1 + 64 + padding) / 8;
    std::vector<word_t> hash(hLength / 4, 0);
    memset(hash.data(), 0, hLength);
    memcpy(hash.data(), message.data(), mLength);

    hash[0].bytes[mLength] = 0b10000000;
    swapEndianWrite(&hash[0].bytes[hLength - 8], (char*)&mLengthBits, 8);

    std::array<unsigned int, 64> mQueue;
    std::array<unsigned int, 8> hValues{sha224hValues};
    for(int i = 0; i < hash.size() / 16; i++) {
        for(int j = 0; j < 16; j++) {
            swapEndianWrite((char*)&mQueue[j], (char*)&hash[i * 16 + j].word, 4);
        }

        for(int j = 16; j < 64; j++) {
            mQueue[j] = s1(mQueue[j-2]) + mQueue[j-7] + s0(mQueue[j-15]) + mQueue[j-16];
        }

        std::array<unsigned int, 8> registers{hValues};
        sha256Compression(registers, mQueue);

        for(int j = 0; j < 8; j++) {
            hValues[j] = registers[j] + hValues[j];
        }
    }

    std::stringstream ss;
    for(int i = 0; i < 7; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << hValues[i];
    }

    return ss.str();
}
