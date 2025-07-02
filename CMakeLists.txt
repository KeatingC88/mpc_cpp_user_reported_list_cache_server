cmake_minimum_required(VERSION 3.16)
project(mpc_cpp_online_status_server)

set(CMAKE_CXX_STANDARD 17)

# Define your executable
add_executable(mpc_cpp_online_status_server
    mpc_cpp_online_status_server.cpp
)

# Include directories for headers
target_include_directories(mpc_cpp_online_status_server PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp_redis/install/include
    ${CMAKE_SOURCE_DIR}/tacopie/includes
    ${CMAKE_SOURCE_DIR}/crow/include
    ${CMAKE_SOURCE_DIR}/asio/asio/include
)

# Link against Redis client and networking
target_link_directories(mpc_cpp_online_status_server PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp_redis/install/lib/Release
    ${CMAKE_SOURCE_DIR}/tacopie/build/lib/Release
)

target_link_libraries(mpc_cpp_online_status_server
    cpp_redis
    tacopie
    ws2_32  # Required on Windows for sockets
)
