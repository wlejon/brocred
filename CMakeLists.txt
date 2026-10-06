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

# Coverage. Scoped to a top-level build: a consumer that add_subdirectory()s
# brocred has no business having its own build instrumented from in here.
option(BROCRED_COVERAGE "Instrument the build for gcov coverage (GCC/Clang)" OFF)
if(BROCRED_COVERAGE AND _brocred_top_level)
    if(MSVC)
        message(FATAL_ERROR "BROCRED_COVERAGE requires GCC or Clang (gcov instrumentation); MSVC is unsupported.")
    endif()
    # Atomic counters: the PolicyKit agent and Secret Service provider run
    # worker threads, and racing plain counters leave negative branch counts
    # gcov cannot read.
    add_compile_options(--coverage -fprofile-update=atomic -O0 -g)
    add_link_options(--coverage)
    message(STATUS "brocred: coverage instrumentation ON (-O0)")
endif()

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
    list(APPEND BROCRED_SOURCES ${_win_sources} src/unavailable/desktop_agents.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Optional system integrations. AUTO uses them when the development files
    # are present; ON makes a missing one a configure error; OFF never uses it.
    # Without sd-bus the store is the file keystore (Secret Service and fprintd
    # report themselves unavailable); without PAM verify_password() fails with
    # an explanatory error. brocred::compiled_features() says which were built.
    set(BROCRED_WITH_SDBUS AUTO CACHE STRING "Secret Service + fprintd over sd-bus (libsystemd): AUTO, ON or OFF")
    set(BROCRED_WITH_PAM AUTO CACHE STRING "Password verification through PAM: AUTO, ON or OFF")
    set_property(CACHE BROCRED_WITH_SDBUS PROPERTY STRINGS AUTO ON OFF)
    set_property(CACHE BROCRED_WITH_PAM PROPERTY STRINGS AUTO ON OFF)

    find_package(PkgConfig REQUIRED)
    find_package(Threads REQUIRED)

    set(BROCRED_HAVE_SDBUS OFF)
    if(NOT BROCRED_WITH_SDBUS STREQUAL "OFF")
        if(BROCRED_WITH_SDBUS STREQUAL "ON")
            pkg_check_modules(BROCRED_SDBUS REQUIRED IMPORTED_TARGET libsystemd>=246)
        else()
            pkg_check_modules(BROCRED_SDBUS QUIET IMPORTED_TARGET libsystemd>=246)
        endif()
        if(BROCRED_SDBUS_FOUND)
            set(BROCRED_HAVE_SDBUS ON)
        endif()
    endif()

    set(BROCRED_HAVE_PAM OFF)
    if(NOT BROCRED_WITH_PAM STREQUAL "OFF")
        find_path(BROCRED_PAM_INCLUDE_DIR security/pam_appl.h)
        find_library(BROCRED_PAM_LIBRARY pam)
        if(BROCRED_PAM_INCLUDE_DIR AND BROCRED_PAM_LIBRARY)
            set(BROCRED_HAVE_PAM ON)
        elseif(BROCRED_WITH_PAM STREQUAL "ON")
            message(FATAL_ERROR "BROCRED_WITH_PAM=ON but PAM headers/library were not found (libpam0g-dev / pam-devel)")
        endif()
    endif()
    message(STATUS "brocred: sd-bus (Secret Service, fprintd): ${BROCRED_HAVE_SDBUS}; PAM: ${BROCRED_HAVE_PAM}")

    file(GLOB _linux_sources CONFIGURE_DEPENDS src/linux/*.cpp)
    list(APPEND BROCRED_SOURCES ${_linux_sources})
    if(BROCRED_HAVE_SDBUS)
        find_package(OpenSSL REQUIRED)
        file(GLOB _dbus_sources CONFIGURE_DEPENDS src/linux/dbus/*.cpp)
        list(APPEND BROCRED_SOURCES ${_dbus_sources})
        file(GLOB _polkit_sources CONFIGURE_DEPENDS src/linux/polkit/*.cpp)
        list(APPEND BROCRED_SOURCES ${_polkit_sources})
        file(GLOB _secret_service_sources CONFIGURE_DEPENDS src/linux/secret_service/*.cpp)
        list(APPEND BROCRED_SOURCES ${_secret_service_sources})
    else()
        list(APPEND BROCRED_SOURCES src/unavailable/desktop_agents.cpp)
    endif()
elseif(APPLE)
    enable_language(OBJCXX)
    set(CMAKE_OBJCXX_STANDARD 20)
    set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
    find_package(Threads REQUIRED)
    file(GLOB _mac_sources CONFIGURE_DEPENDS src/mac/*.cpp src/mac/*.mm)
    list(APPEND BROCRED_SOURCES ${_mac_sources} src/unavailable/desktop_agents.cpp)
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
    target_link_libraries(brocred PUBLIC Threads::Threads)
    if(BROCRED_HAVE_SDBUS)
        target_link_libraries(brocred PRIVATE PkgConfig::BROCRED_SDBUS OpenSSL::Crypto)
        target_compile_definitions(brocred PRIVATE BROCRED_HAVE_SDBUS=1)
    endif()
    if(BROCRED_HAVE_PAM)
        target_include_directories(brocred PRIVATE ${BROCRED_PAM_INCLUDE_DIR})
        target_link_libraries(brocred PRIVATE ${BROCRED_PAM_LIBRARY})
        target_compile_definitions(brocred PRIVATE BROCRED_HAVE_PAM=1)
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
