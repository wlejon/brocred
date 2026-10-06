add_library(brocred_api STATIC
    api.cpp
    host_class.cpp
    native_auth.cpp
    native_biometrics.cpp
    native_secrets.cpp
    native_polkit.cpp
)

target_include_directories(brocred_api PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
)

target_link_libraries(brocred_api PUBLIC
    brocred
    bronze_runtime_shared
)

target_compile_features(brocred_api PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(brocred_api PRIVATE /W4 /permissive- /utf-8 /MP)
else()
    target_compile_options(brocred_api PRIVATE -Wall -Wextra -Wpedantic)
endif()
