cmake_minimum_required(VERSION 3.16)

project(ados22 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)
find_library(M_LIBRARY NAMES m)
find_package(Threads REQUIRED)

add_library(ados22 STATIC
    src/ados22.cpp
    src/core.cpp
    src/elgamal.cpp)
add_library(ados22::ados22 ALIAS ados22)

target_include_directories(ados22
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${NTL_INCLUDE_PATHS}"
        "${GMP_INCLUDE_PATHS}"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(ados22
    PUBLIC
        "${NTL_LIBRARIES}"
        "${GMP_LIBRARIES}"
        Threads::Threads)

if(M_LIBRARY)
    target_link_libraries(ados22 PUBLIC "${M_LIBRARY}")
endif()

add_executable(ados22_demo demo/main.cpp)
target_link_libraries(ados22_demo PRIVATE ados22)

if(PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
