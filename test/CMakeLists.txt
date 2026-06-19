find_package(GTest REQUIRED)

add_executable(zip_bruteforce_tests
    test_charset.cpp
    test_password_generator.cpp
    test_archive_manager.cpp
    test_password_checker.cpp
    test_brute_force_engine.cpp
    test_results_storage.cpp
)

target_include_directories(zip_bruteforce_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${GTEST_INCLUDE_DIRS}
)

target_link_libraries(zip_bruteforce_tests PRIVATE
    zip_bruteforce_core
    GTest::gtest
    GTest::gtest_main
    pthread
)

include(GoogleTest)
gtest_discover_tests(zip_bruteforce_tests)
