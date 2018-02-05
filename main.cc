#include <iostream>
#include <fstream>
#include <vector>

#include "sha.hh"

int main(int argc, char** argv) {
    if(argc != 3) {
        std::cout << "Incorrect Input\n";
        return -1;
    }

    std::string sha{argv[1]};
    std::string filename{argv[2]};

    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if(!file.is_open()) {
        std::cout << "Couldn't open file " << filename << '\n';
    }

    std::vector<char> bytes;
    file.seekg(0, std::ios::end);
    unsigned int size = file.tellg();
    file.seekg(0, std::ios::beg);
    bytes.resize(size);

    file.read(bytes.data(), size);

    if(std::string{sha} == "224") {
        std::string hash224 = sha224(bytes);
        std::cout << "SHA-224 of \'" << filename << "\' -> " << hash224 << '\n';
    } else if(std::string{sha} == "256") {
        std::string hash256 = sha256(bytes);
        std::cout << "SHA-256 of \'" << filename << "\' -> " << hash256 << '\n';
    } else {
        std::cout << "Unknown SHA method \'" << sha << "\'\n";
    }
}
