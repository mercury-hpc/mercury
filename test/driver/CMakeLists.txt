cmake_minimum_required(VERSION 2.8)
project(IOFSL_SHIPPER_TEST_DRIVER CXX)

set(KWSYS_NAMESPACE iofsl_shipper_sys)
set(KWSYS_USE_SystemTools 1)
set(KWSYS_USE_Process 1)
set(KWSYS_USE_RegularExpression 1)
add_subdirectory(kwsys)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/kwsys)

add_executable(shipper_test_driver shipper_test_driver.cxx)
target_link_libraries(shipper_test_driver iofsl_shipper_sys)
