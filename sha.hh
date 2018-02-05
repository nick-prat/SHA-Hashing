#ifndef _SHA_H
#define _SHA_H

#include <vector>
#include <string>

std::string sha256(const std::vector<char>& message);
std::string sha224(const std::vector<char>& message);

#endif // _SHA_H
