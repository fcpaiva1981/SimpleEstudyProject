cmake_minimum_required(VERSION 3.31)
project(SimpleEstudyProject)

set(CMAKE_CXX_STANDARD 20)

 
add_executable(SimpleEstudyProject main.cpp)


set(LIBSSH_INCLUDE_DIR "/opt/homebrew/include")

set(LIBSSH_LIB_DIR "/opt/homebrew/lib")

set(LIBSSH_LIBRARY_NAME ssh)

target_include_directories(SimpleEstudyProject PRIVATE ${LIBSSH_INCLUDE_DIR})


target_link_directories(SimpleEstudyProject PRIVATE ${LIBSSH_LIB_DIR})


target_link_libraries(SimpleEstudyProject PRIVATE ${LIBSSH_LIBRARY_NAME})