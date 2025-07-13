cmake_minimum_required(VERSION 3.16)
project(mpc_cpp_online_status_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TACOPIE_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/tacopie/includes")
set(TACOPIE_LIBRARY tacopie)

add_definitions(-D_WIN32_WINNT=0x0601)

# Add subdirectories
add_subdirectory(tacopie)

add_subdirectory(cpp_redis)

# Required for standalone Asio
add_definitions(-DASIO_STANDALONE)

# Include headers
include_directories(
    ${CMAKE_SOURCE_DIR}/crow/include
    ${CMAKE_SOURCE_DIR}/asio/asio/include
    ${CMAKE_SOURCE_DIR}/cpp_redis/includes
    ${CMAKE_SOURCE_DIR}/tacopie/includes
)

# Define the executable
add_executable(mpc_cpp_online_status_server mpc_cpp_online_status_server.cpp)

# Link libraries
target_link_libraries(mpc_cpp_online_status_server
    cpp_redis
    tacopie
)