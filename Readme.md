# Dependencies -- If you wish to download them manually
Library	Repo URL
Crow	https://github.com/CrowCpp/crow.git
ASIO	https://github.com/chriskohlhoff/asio.git
tacopie	https://github.com/Cylix/tacopie.git
cpp_redis	https://github.com/Cylix/cpp_redis.git
jwt-cpp	https://github.com/Thalhammer/jwt-cpp.git
nlohmann	https://github.com/nlohmann/json.git


# Example .Env File you must create
HOST_IP_ADDRESS=127.0.0.1
HOST_PORT_ADDRESS=8000
REDIS_HOST_ADDRESS=127.0.0.1
REDIS_PORT_ADDRESS=6379

ENCRYPTION_KEY=(enter 32 character string here
ENCRYPTION_IV=(enter 16 character string here)

JWT_ISSUER_KEY=(Only use if ur encrpting values)
JWT_CLIENT_KEY=(you may have to modify the code to remove these)

# Cmakeuplist.txt
cmake_minimum_required(VERSION 3.16)
project(mpc_cpp_online_status_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


add_definitions(-DASIO_STANDALONE)

set(TACOPIE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/tacopie/includes")
set(TACOPIE_LIBRARY tacopie)

add_definitions(-D_WIN32_WINNT=0x0601)
find_package(OpenSSL REQUIRED)


add_subdirectory(jwt-cpp)

add_subdirectory(tacopie)

add_subdirectory(cpp_redis)

include_directories(
    ${CMAKE_SOURCE_DIR}/crow/include
    ${CMAKE_SOURCE_DIR}/asio/asio/include
    ${CMAKE_SOURCE_DIR}/cpp_redis/includes
    ${CMAKE_SOURCE_DIR}/tacopie/includes
    ${CMAKE_SOURCE_DIR}/jwt-cpp/include
    ${CMAKE_SOURCE_DIR}/nlohmann/include
)

add_executable(mpc_cpp_online_status_server mpc_cpp_online_status_server.cpp)

target_link_libraries(mpc_cpp_online_status_server
    PRIVATE 
    OpenSSL::Crypto
    cpp_redis
    tacopie
)


# Cmake Build Instructions (preferred method)
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release

# Example POST - SET

{
  "id": "Base64EncryptedUserId",
  "online_status": "Base64EncryptedStatus",
  "token": "JWTToken"
}

# Example POST - GET
{
  "id": "Base64EncryptedUserId",
  "token": "JWTToken"
}

# Docker Option 1) for CLI command:
1) Navigate CLI to folder and use
docker compose -f mpc_cpp_online_status_server.yaml up -d

# Docker Option 2) startup for CLI command:
1) Navigate CLI to folder and use
docker build -t mpc_cpp_online_status_server_rom .
docker run -d -p {SERVER_NETWORK_PORT_NUMBER}:{DOCKER_CONTAINER_PORT_NUMBER} --name mpc_cpp_online_status_server mpc_cpp_online_status_server_rom


# Other Notes
.Env file must be in the same directory as the .exe if using Cmake.


# Directory Layout
mpc_cpp_online_status_server/
│
├── .env                          # Environment variables used by the server and docker-compose
├── Dockerfile                    # Container image build script
├── docker-compose.yaml           # Compose file to run the server + Redis
├── CMakeLists.txt                # CMake build script
├── README.md                     # Documentation and usage
│
├── mpc_cpp_online_status_server.cpp   # Main C++ source file (your current file)
│
├── jwt-cpp/                      # JWT handling library (added via submodule)
│   └── include/
│
├── crow/                         # Crow framework (submodule)
│   └── include/
│
├── asio/                         # ASIO library (standalone networking lib)
│   └── asio/include/
│
├── tacopie/                      # TCP client lib required by cpp_redis
│   └── includes/
│
├── cpp_redis/                    # Redis C++ client
│   ├── includes/
│   └── sources/
│
└── nlohmann/                     # JSON for Modern C++ header-only lib
    └── include/json.hpp


# Directory layout of the Cmake Build

mpc_cpp_online_status_server/
├── build/
│   └── Release/
│       ├── mpc_cpp_online_status_server.exe   # Your compiled C++ server
│       ├── .env  (don't forget me).