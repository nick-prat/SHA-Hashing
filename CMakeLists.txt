cmake_minimum_required(VERSION 3.5)

project(hash)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -pedantic -std=c++17")

set(SOURCE_FILES
    main.cc
    sha.cc
)

add_executable(hash.out ${SOURCE_FILES})
