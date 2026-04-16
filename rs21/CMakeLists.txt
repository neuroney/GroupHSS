cmake_minimum_required(VERSION 3.16)

project(rs21 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)
find_library(M_LIBRARY NAMES m)
find_package(Threads REQUIRED)

add_library(rs21 STATIC
    src/rs21.cpp
    src/core.cpp
    src/dj.cpp)
add_library(rs21::rs21 ALIAS rs21)

target_include_directories(rs21
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${NTL_INCLUDE_PATHS}"
        "${GMP_INCLUDE_PATHS}"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(rs21
    PUBLIC
        "${NTL_LIBRARIES}"
        "${GMP_LIBRARIES}"
        Threads::Threads)

if(M_LIBRARY)
    target_link_libraries(rs21 PUBLIC "${M_LIBRARY}")
endif()

add_executable(rs21_demo demo/main.cpp)
target_link_libraries(rs21_demo PRIVATE rs21)

if(PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
