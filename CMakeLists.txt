cmake_minimum_required(VERSION 3.20)
project(zip_bruteforce_research VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -mtune=native")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBZIP REQUIRED libzip)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_library(zip_bruteforce_core STATIC
    src/generator/charset.cpp
    src/generator/password_generator.cpp
    src/archive/archive_manager.cpp
    src/checker/password_checker.cpp
    src/engine/brute_force_engine.cpp
    src/stats/stats_collector.cpp
    src/storage/results_storage.cpp
    src/app/experiment_runner.cpp
    src/app/cli_parser.cpp
    src/gpu/metal_kernel.mm
    src/gpu/gpu_checker.cpp
    src/gpu/zipcrypto_util.cpp
)

target_include_directories(zip_bruteforce_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${LIBZIP_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_directories(zip_bruteforce_core PUBLIC
    ${LIBZIP_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
    ${SQLITE3_LIBRARY_DIRS}
)

target_link_libraries(zip_bruteforce_core PUBLIC
    ${LIBZIP_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

add_executable(zipbrute src/main.cpp)
target_link_libraries(zipbrute PRIVATE zip_bruteforce_core "-framework Foundation" "-framework Metal")
set_target_properties(zipbrute PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

enable_testing()
add_subdirectory(test)
