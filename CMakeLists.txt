cmake_minimum_required(VERSION 3.24)

project(brocred VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(_brocred_top_level OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_brocred_top_level ON)
endif()

option(BROCRED_BUILD_TESTS "Build the brocred tests" ${_brocred_top_level})

if(MSVC AND _brocred_top_level)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

function(brocred_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /MP)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

file(GLOB BROCRED_SOURCES CONFIGURE_DEPENDS src/common/*.cpp)

if(WIN32)
    file(GLOB _win_sources CONFIGURE_DEPENDS src/win/*.cpp)
    list(APPEND BROCRED_SOURCES ${_win_sources})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    find_package(Threads REQUIRED)
    pkg_check_modules(BROCRED_SDBUS REQUIRED IMPORTED_TARGET libsystemd>=246)
    pkg_check_modules(BROCRED_PAM QUIET IMPORTED_TARGET pam)

    file(GLOB _linux_sources CONFIGURE_DEPENDS
        src/linux/*.cpp
        src/linux/dbus/*.cpp)
    list(APPEND BROCRED_SOURCES ${_linux_sources})
elseif(APPLE)
    enable_language(OBJCXX)
    set(CMAKE_OBJCXX_STANDARD 20)
    set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
    find_package(Threads REQUIRED)
    file(GLOB _mac_sources CONFIGURE_DEPENDS src/mac/*.cpp src/mac/*.mm)
    list(APPEND BROCRED_SOURCES ${_mac_sources})
else()
    message(FATAL_ERROR "brocred implements Windows, Linux and macOS backends only")
endif()

add_library(brocred STATIC ${BROCRED_SOURCES})
add_library(brocred::brocred ALIAS brocred)

target_include_directories(brocred
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

brocred_warnings(brocred)

if(WIN32)
    target_compile_definitions(brocred PRIVATE
        NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00)
    target_link_libraries(brocred PRIVATE
        advapi32 winbio windowsapp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(brocred
        PUBLIC
            Threads::Threads
        PRIVATE
            PkgConfig::BROCRED_SDBUS)
    if(BROCRED_PAM_FOUND)
        target_link_libraries(brocred PRIVATE PkgConfig::BROCRED_PAM)
    else()
        find_library(PAM_LIB pam REQUIRED)
        target_link_libraries(brocred PRIVATE ${PAM_LIB})
    endif()
elseif(APPLE)
    target_compile_options(brocred PRIVATE $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>)
    target_link_libraries(brocred
        PUBLIC
            Threads::Threads
        PRIVATE
            "-framework Foundation"
            "-framework Security"
            "-framework OpenDirectory"
            "-framework LocalAuthentication")
endif()

if(BROCRED_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
