cmake_minimum_required(VERSION 3.15.0)
project(ntoseye VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)

find_package(Zydis)

configure_file(version.h.in version.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB GLOBBED_SOURCES CONFIGURE_DEPENDS "ntoseye/*.cpp")

add_executable(ntoseye ${GLOBBED_SOURCES})
target_link_libraries(ntoseye readline Zydis curl LLVM)
target_link_options(ntoseye PRIVATE -rdynamic -g)
