MPC C++ Online Status Server

A lightweight HTTP API built with Crow and Redis Cluster support, using C++17.It supports AES-256-CBC encrypted payloads, JWT decoding, and real-time online status tracking as a cached server.

📦 Features

AES-256-CBC encryption compatible with CryptoJS

JWT decoding using jwt-cpp

Redis Cluster or Redis Proxy support via cpp_redis

Crow framework for high-performance HTTP routing

CMake-powered build with modular source structure

🔧 Prerequisites

CMake ≥ 3.16

A C++17-compatible compiler (MSVC, Clang, GCC)

OpenSSL development libraries

On Windows: install via vcpkg or manually on your operating system

Git (to clone with submodules)

Redis Cluster or proxy running (optional for core API)

📁 Dependency Submodules

This project assumes all required libraries are present in the project root folder as Git submodules:

Library

Repo URL

Crow

https://github.com/CrowCpp/crow.git

ASIO

https://github.com/chriskohlhoff/asio.git

tacopie

https://github.com/Cylix/tacopie.git

cpp_redis

https://github.com/Cylix/cpp_redis.git

jwt-cpp

https://github.com/Thalhammer/jwt-cpp.git

To fetch all dependencies:

git submodule update --init --recursive

🧰 CMake Instructions

Assuming all submodules are in the root:

cmake_minimum_required(VERSION 3.16)
project(mpc_cpp_online_status_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DASIO_STANDALONE)
add_definitions(-D_WIN32_WINNT=0x0601)

set(TACOPIE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/tacopie/includes")
set(TACOPIE_LIBRARY tacopie)

find_package(OpenSSL REQUIRED)

# Add subdirectories
add_subdirectory(jwt-cpp)
add_subdirectory(tacopie)
add_subdirectory(cpp_redis)

# Include headers
include_directories(
    ${CMAKE_SOURCE_DIR}/crow/include
    ${CMAKE_SOURCE_DIR}/asio/asio/include
    ${CMAKE_SOURCE_DIR}/cpp_redis/includes
    ${CMAKE_SOURCE_DIR}/tacopie/includes
    ${CMAKE_SOURCE_DIR}/jwt-cpp/include
)

# Define the executable
add_executable(mpc_cpp_online_status_server mpc_cpp_online_status_server.cpp)

# Link libraries
target_link_libraries(mpc_cpp_online_status_server
    PRIVATE
    OpenSSL::Crypto
    cpp_redis
    tacopie
)



===== End of Cmake =======


🚀 Build Instructions

🔹 Clone the Repo with Submodules

git clone --recurse-submodules https://github.com/your_username/mpc_cpp_online_status_server.git
cd mpc_cpp_online_status_server

If already cloned:

git submodule update --init --recursive

🔹 Build with CMake

mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

ℹ️ If OpenSSL is not found:

On Windows, use vcpkg:

./vcpkg install openssl
cmake -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake ..

📤 Running the Server

The executable will be created in the build/ directory:

./mpc_cpp_online_status_server

Server will run on:http://localhost:port/

🔐 AES + JWT Setup

The project supports decrypting AES-256-CBC tokens created using JavaScript CryptoJS. Example config:

ENCRYPTION_KEY=(32 bytes)
ENCRYPTION_IV=(16 bytes)

Compatible with CryptoJS:


📩 API Example (POST)

POST /set HTTP/1.1
Host: localhost:port
Content-Type: application/json
post
{
  "user_id": "encryption-value",
  "status": "encryption-value"
}
post
{
  "id": "encryption-value",
}
The server will decrypt user_id and status using AES-256-CBC and store the status in Redis under the user’s ID.