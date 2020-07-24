cmake_minimum_required(VERSION 2.8.12.2 FATAL_ERROR)
project(MERCURY_TEST_DRIVER CXX)

include(CheckAsan)
include(CheckTsan)
include(CheckUbsan)

set(KWSYS_NAMESPACE mercury_sys)
set(KWSYS_USE_SystemTools 1)
set(KWSYS_USE_Process 1)
set(KWSYS_USE_RegularExpression 1)
add_subdirectory(kwsys)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/kwsys)

add_executable(mercury_test_driver mercury_test_driver.cxx)
target_link_libraries(mercury_test_driver mercury_sys)
