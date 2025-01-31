cmake_minimum_required(VERSION 3.10)

# Project name
project(bmap-writer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find pkgconfig
find_package(PkgConfig REQUIRED)

# Find TinyXML-2
pkg_check_modules(TINYXML2 REQUIRED tinyxml2)
if (TINYXML2_FOUND)
    include_directories(${TINYXML2_INCLUDE_DIR})
else()
    message(FATAL_ERROR "tinyxml2 library not found")
endif()


# Find libarchive
find_package(LibArchive REQUIRED)
if (LibArchive_FOUND)
    include_directories(${LIBARCHIVE_INCLUDE_DIR})
else()
    message(FATAL_ERROR "libarchive not found")
endif()

if (NOT DEFINED DEFAULT_READ_BLK_SIZE)
  set(DEFAULT_READ_BLK_SIZE 16384)
endif()

execute_process(
    COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} describe --tags
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_compile_definitions(READ_BLK_SIZE=${DEFAULT_READ_BLK_SIZE})
add_compile_definitions(GIT_VERSION="${GIT_VERSION}")

# Add the executable
add_executable(bmap-writer bmap-writer.cpp sha256.cpp)
target_compile_options(bmap-writer PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Link the libraries
target_link_libraries(bmap-writer ${TINYXML2_LIBRARIES} ${LibArchive_LIBRARIES})

# Specify the install rules
install(TARGETS bmap-writer DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME bmap-writer-test COMMAND ./bmap-writer-test.sh)
