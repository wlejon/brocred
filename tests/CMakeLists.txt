# brocred test harness. Exit code 77 is a skip, nonzero is a failure.
function(brocred_test name)
    cmake_parse_arguments(T "" "TIMEOUT" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_link_libraries(${name} PRIVATE brocred ${T_LIBS})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src)
    brocred_warnings(${name})

    if(WIN32)
        target_compile_definitions(${name} PRIVATE
            NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00)
    elseif(APPLE)
        target_compile_options(${name} PRIVATE $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>)
    endif()

    if(NOT T_TIMEOUT)
        set(T_TIMEOUT 60)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT ${T_TIMEOUT} SKIP_RETURN_CODE 77)
endfunction()

# Common tests across all platforms
brocred_test(test_event_queue SOURCES common/test_event_queue.cpp)
brocred_test(test_memory_keystore SOURCES common/test_memory_keystore.cpp)
brocred_test(test_file_keystore SOURCES common/test_file_keystore.cpp)
brocred_test(test_desktop_agents SOURCES common/test_desktop_agents.cpp)

if(WIN32)
    brocred_test(test_win_credentials SOURCES win/test_win_credentials.cpp)
    brocred_test(test_win_cmdkey_oracle SOURCES win/test_win_cmdkey_oracle.cpp)
    brocred_test(test_win_verifier SOURCES win/test_win_verifier.cpp)
    brocred_test(test_win_biometrics SOURCES win/test_win_biometrics.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    brocred_test(test_linux_credentials SOURCES linux/test_linux_credentials.cpp)
    brocred_test(test_linux_secret_tool_oracle SOURCES linux/test_linux_secret_tool_oracle.cpp)
    brocred_test(test_linux_verifier SOURCES linux/test_linux_verifier.cpp)
    brocred_test(test_linux_biometrics SOURCES linux/test_linux_biometrics.cpp)
    if(BROCRED_HAVE_SDBUS)
        brocred_test(test_linux_dbus_client SOURCES linux/test_linux_dbus_client.cpp LIBS PkgConfig::BROCRED_SDBUS OpenSSL::Crypto)
        brocred_test(test_crypto_dh SOURCES linux/test_crypto_dh.cpp LIBS OpenSSL::Crypto)
        brocred_test(test_secret_service SOURCES linux/test_secret_service.cpp LIBS PkgConfig::BROCRED_SDBUS OpenSSL::Crypto)
        brocred_test(test_polkit_agent SOURCES linux/test_polkit_agent.cpp LIBS PkgConfig::BROCRED_SDBUS)
    endif()
    # Tells the feature test what this configuration was built with.
    brocred_test(test_linux_features SOURCES linux/test_linux_features.cpp)
    target_compile_definitions(test_linux_features PRIVATE
        EXPECT_SDBUS=$<BOOL:${BROCRED_HAVE_SDBUS}> EXPECT_PAM=$<BOOL:${BROCRED_HAVE_PAM}>)
elseif(APPLE)
    brocred_test(test_mac_credentials SOURCES mac/test_mac_credentials.mm)
    brocred_test(test_mac_security_oracle SOURCES mac/test_mac_security_oracle.mm)
    brocred_test(test_mac_verifier SOURCES mac/test_mac_verifier.mm)
    brocred_test(test_mac_biometrics SOURCES mac/test_mac_biometrics.mm)
    # Both may swap the default keychain (BROCRED_TEST_TEMP_KEYCHAIN=1): never concurrently.
    set_tests_properties(test_mac_credentials test_mac_security_oracle PROPERTIES RESOURCE_LOCK user_keychain)
endif()

if(BROCRED_ENABLE_API)
    add_executable(brocred_test_api
        test_cred_api.cpp
    )
    target_include_directories(brocred_test_api PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
        ${PROJECT_SOURCE_DIR}
    )
    target_link_libraries(brocred_test_api PRIVATE
        brocred_api
        brocred
        bronze_runtime_shared
    )
    if(MSVC)
        target_compile_options(brocred_test_api PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(brocred_test_api PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
        add_custom_command(TARGET brocred_test_api POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brocred_test_api>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_LINKER_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brocred_test_api>
        )
    else()
        target_compile_options(brocred_test_api PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(NOT BRASS_HOST_BACKEND)
        message(STATUS "brocred: brocred_test_api not registered (brass has no code generator for this target)")
    else()
        add_test(NAME brocred_test_api COMMAND brocred_test_api)
        set_tests_properties(brocred_test_api PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)

        # A collection at every allocation over a Debug bronze (-O0, and
        # instrumented in the coverage job) takes minutes, not seconds. The
        # limit is there to catch a hang, not to time the run.
        add_test(NAME brocred_test_api_gc_stress COMMAND brocred_test_api)
        set_tests_properties(brocred_test_api_gc_stress PROPERTIES
            TIMEOUT 600
            SKIP_RETURN_CODE 77
            ENVIRONMENT "BRONZE_GC_STRESS=1;BRONZE_GC_POISON=1"
        )
        if(WIN32)
            set_tests_properties(brocred_test_api PROPERTIES
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brocred_test_api>;$ENV{PATH}")
            set_property(TEST brocred_test_api_gc_stress APPEND PROPERTY
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brocred_test_api>;$ENV{PATH}")
        endif()
    endif()
endif()

# Every test executable links no_dialogs.cpp (see the file).
if(WIN32)
    get_property(_test_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_t IN LISTS _test_targets)
        get_target_property(_type ${_t} TYPE)
        if(_type STREQUAL "EXECUTABLE")
            target_sources(${_t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/no_dialogs.cpp)
        endif()
    endforeach()
endif()
