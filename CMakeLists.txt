cmake_minimum_required(VERSION 3.13)

project(ptls_mbedtls_trial
        VERSION 0.0.0.1
        DESCRIPTION "Testing MBEDTLS and picotls"
        LANGUAGES C CXX)

find_package(Threads REQUIRED)

option(ENABLE_ASAN "Enable AddressSanitizer (ASAN) for debugging" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan) for debugging" OFF)

message(STATUS "Initial CMAKE_C_FLAGS=${CMAKE_C_FLAGS}")

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakePushCheckState)

if(ENABLE_ASAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
    check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
        message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
    endif()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -fsanitize=address)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fsanitize=address)
    list(APPEND PICOQUIC_LINKER_FLAGS -fsanitize=address)
endif()

if(ENABLE_UBSAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=undefined")
    check_c_compiler_flag(-fsanitize=undefined C__fsanitize_undefined_VALID)
    check_cxx_compiler_flag(-fsanitize=undefined CXX__fsanitize_undefined_VALID)
    cmake_pop_check_state()
    if(NOT C__fsanitize_undefined_VALID OR NOT CXX__fsanitize_undefined_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but not supported!")
    endif()
    list(PREPEND PICOQUIC_ADDITIONAL_C_FLAGS -fsanitize=undefined)
    list(PREPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fsanitize=undefined)
    list(PREPEND PICOQUIC_LINKER_FLAGS -fsanitize=undefined)

    # Ease detecting of "Runtime errors". If such an error is found, print a verbose
    # error report and exit the program
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fno-sanitize-recover")
    check_c_compiler_flag(-fno-sanitize-recover C__fnosanitize_recover_VALID)
    check_cxx_compiler_flag(-fno-sanitize-recover CXX__fnosanitize_recover_VALID)
    cmake_pop_check_state()
    if(NOT C__fnosanitize_recover_VALID OR NOT CXX__fnosanitize_recover_VALID)
        message(FATAL_ERROR "ENABLE_UBSAN was requested, but fno-sanitize-recover is not supported!")
    endif()
    list(APPEND PICOQUIC_ADDITIONAL_C_FLAGS -fno-sanitize-recover)
    list(APPEND PICOQUIC_ADDITIONAL_CXX_FLAGS -fno-sanitize-recover)
    list(APPEND PICOQUIC_LINKER_FLAGS -fno-sanitize-recover)
endif()

set(PTLS_MBEDTLS_LIBRARY_FILES
    lib/ptls_mbedtls.c)

set(PTLS_MBEDTLS_CORE_HEADERS
     lib/ptls_mbedtls.h)

OPTION(PICOQUIC_FETCH_PTLS "Fetch PicoTLS during configuration" OFF)
if(PICOQUIC_FETCH_PTLS)
    include(FetchContent)
    FetchContent_Declare(picotls
        GIT_REPOSITORY      https://github.com/h2o/picotls.git
        GIT_TAG             7d294ab4f2e0ed749b4bcfaf533225a4e0c096f7)
    FetchContent_MakeAvailable(picotls)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )

# set_picoquic_compile_settings(TARGET) makes is easy to consistently
# assign compiler build options to each of the following targets
macro(set_ptls_mbedtls_compile_settings)
    set_target_properties(${ARGV0}
        PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS YES)
    set_target_properties(${ARGV0}
        PROPERTIES
            CXX_STANDARD 11
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS YES)
    target_compile_options(${ARGV0}
        PRIVATE
            $<$<C_COMPILER_ID:Clang>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:AppleClang>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:GNU>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -frename-registers -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_C_FLAGS}>
            $<$<C_COMPILER_ID:MSVC>: >
            $<$<CXX_COMPILER_ID:Clang>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:AppleClang>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:GNU>: -O3 -Wall -fno-exceptions
                -fno-signed-zeros -frename-registers -fno-trapping-math
                ${PICOQUIC_ADDITIONAL_CXX_FLAGS}>
            $<$<CXX_COMPILER_ID:MSVC>: >)
    target_compile_definitions(${ARGV0} PRIVATE ${PICOQUIC_COMPILE_DEFINITIONS})
    target_link_options(${ARGV0} PRIVATE ${PICOQUIC_LINKER_FLAGS})
endmacro()


add_library(ptls_mbedtls-core ${PICOQUIC_CORE_HEADERS} ${PICOQUIC_LIBRARY_FILES})
target_include_directories(ptls_mbedtls-core
    PRIVATE
        ${PTLS_INCLUDE_DIRS}
    PUBLIC
        include)
target_link_libraries(ptls_mbedtls-core
    PRIVATE
        ${OPENSSL_LIBRARIES}
    PUBLIC
        ${PTLS_LIBRARIES}
        Threads::Threads)
set_picoquic_compile_settings(ptls_mbedtls-core)


add_executable(ptls_mbedtls_trial
    src/mbedtls_trial.c)
target_link_libraries(ptls_mbedtls_trial
    PRIVATE
        ${PTLS_LIBRARIES}
        # ${OPENSSL_LIBRARIES}
        picoquic-log
        picoquic-core
        picohttp-core)
target_include_directories(ptls_mbedtls_trial PRIVATE include)
set_ptls_mbedtls_compile_settings(ptls_mbedtls_trial)

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES})

# Specify Install targets
install(TARGETS ptls_mbedtls_trial ptls_mbedtls-core
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES
        ${PTLS_MBEDTLS_CORE_HEADERS}
        DESTINATION include)
