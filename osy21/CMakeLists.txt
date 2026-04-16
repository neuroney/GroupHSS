cmake_minimum_required(VERSION 3.16)

project(osy21 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)
find_library(M_LIBRARY NAMES m)
find_package(Threads REQUIRED)

add_library(osy21 STATIC
    src/osy21.cpp
    src/core.cpp
    src/paillier.cpp)
add_library(osy21::osy21 ALIAS osy21)

target_include_directories(osy21
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${NTL_INCLUDE_PATHS}"
        "${GMP_INCLUDE_PATHS}"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(osy21
    PUBLIC
        "${NTL_LIBRARIES}"
        "${GMP_LIBRARIES}"
        Threads::Threads)

if(M_LIBRARY)
    target_link_libraries(osy21 PUBLIC "${M_LIBRARY}")
endif()

add_executable(osy21_demo demo/main.cpp)
target_link_libraries(osy21_demo PRIVATE osy21)

if(PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
