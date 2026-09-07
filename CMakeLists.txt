cmake_minimum_required(VERSION 3.20)

project(
    pqxdh
    VERSION 0.3.0
    DESCRIPTION "PQXDH revision 3 key agreement library"
    LANGUAGES C
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(PQXDH_BUILD_TESTS "Build the PQXDH test suite" ON)
option(PQXDH_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
option(PQXDH_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(liboqs CONFIG REQUIRED)

find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
    set(PQXDH_SODIUM_TARGET unofficial-sodium::sodium)
    set(PQXDH_SODIUM_PROVIDER "vcpkg")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(PQXDH_SODIUM_TARGET PkgConfig::SODIUM)
    set(PQXDH_SODIUM_PROVIDER "pkg-config")
endif()

# Pinned submodule implementing Signal's randomized XEd25519 signatures.
set(BUILD_TESTING OFF CACHE BOOL "Disable dependency tests" FORCE)
add_subdirectory(libxeddsa EXCLUDE_FROM_ALL)

add_library(pqxdh pqxdh.c)
add_library(PQXDH::pqxdh ALIAS pqxdh)

# Fold libxeddsa's objects into pqxdh so both static and shared installations
# remain self-contained (libsodium stays an ordinary public dependency).
target_sources(pqxdh PRIVATE
    $<TARGET_OBJECTS:xeddsa_objects>
    $<TARGET_OBJECTS:crypto_sign_objects>
    $<TARGET_OBJECTS:crypto_hash_objects>
    $<TARGET_OBJECTS:crypto_hashblocks_objects>
    $<TARGET_OBJECTS:crypto_verify_objects>
    $<TARGET_OBJECTS:fastrandombytes_objects>
    $<TARGET_OBJECTS:crypto_rng_objects>
    $<TARGET_OBJECTS:crypto_stream_objects>
    $<TARGET_OBJECTS:crypto_core_objects>
    $<TARGET_OBJECTS:kernelrandombytes_objects>
)

target_compile_features(pqxdh PUBLIC c_std_11)
target_compile_options(
    pqxdh
    PRIVATE
        $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wshadow;-Wconversion>
)
target_include_directories(
    pqxdh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/libxeddsa/include
        ${CMAKE_CURRENT_SOURCE_DIR}/libxeddsa/ref10/include
)
target_link_libraries(
    pqxdh
    PUBLIC
        OQS::oqs
        OpenSSL::Crypto
        ${PQXDH_SODIUM_TARGET}
)
set_target_properties(
    pqxdh
    PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        WINDOWS_EXPORT_ALL_SYMBOLS YES
)

if(PQXDH_ENABLE_SANITIZERS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(pqxdh PUBLIC -fno-omit-frame-pointer -fsanitize=address,undefined)
        target_link_options(pqxdh PUBLIC -fsanitize=address,undefined)
    else()
        message(FATAL_ERROR "PQXDH_ENABLE_SANITIZERS requires GCC or Clang")
    endif()
endif()

if(PQXDH_BUILD_TESTS)
    enable_testing()
    add_executable(test_pqxdh test_pqxdh.c)
    target_link_libraries(test_pqxdh PRIVATE PQXDH::pqxdh)
    add_test(NAME pqxdh.unit COMMAND test_pqxdh)
endif()

if(PQXDH_BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "PQXDH_BUILD_FUZZERS requires Clang/libFuzzer")
    endif()
    add_executable(fuzz_decode_initial_message fuzz/fuzz_decode_initial_message.c)
    target_link_libraries(fuzz_decode_initial_message PRIVATE PQXDH::pqxdh)
    target_compile_options(fuzz_decode_initial_message PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_decode_initial_message PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

configure_package_config_file(
    cmake/pqxdh-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/pqxdh-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pqxdh"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/pqxdh-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
configure_file(pqxdh.pc.in pqxdh.pc @ONLY)

install(TARGETS pqxdh EXPORT pqxdh-targets)
install(FILES pqxdh.h DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(
    EXPORT pqxdh-targets
    FILE pqxdh-targets.cmake
    NAMESPACE PQXDH::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pqxdh"
)
install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/pqxdh-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/pqxdh-config-version.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/pqxdh"
)
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/pqxdh.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
