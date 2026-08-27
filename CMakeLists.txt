cmake_minimum_required(VERSION 3.29)

project(
  licrypto
  VERSION 0.1.0
  DESCRIPTION "Cryptographic primitives for lito projects"
  LANGUAGES CXX)

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "licrypto only supports clang++")
endif()

if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)

  add_compile_options(
    "$<$<COMPILE_LANGUAGE:CXX>:-fmodules-reduced-bmi>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wall>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wno-gnu-statement-expression>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wno-deprecated-declarations>"
    "$<$<COMPILE_LANGUAGE:CXX>:-Wunknown-attributes>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fsized-deallocation>")
endif()

include(FetchContent)

if(NOT TARGET rstd.std)
  set(RSTD_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    rstd
    GIT_REPOSITORY https://github.com/litocpp/rstd.git
    GIT_TAG 0ec1bc101ab9088f1e3b4ac7be5c1d5e415da8c1)
  FetchContent_MakeAvailable(rstd)
endif()

add_library(licrypto STATIC)
target_compile_features(licrypto PUBLIC cxx_std_20)
target_sources(
  licrypto
  PUBLIC FILE_SET
         modules
         TYPE
         CXX_MODULES
         FILES
         src/base64.cppm
         src/lib.cppm
         src/sha256.cppm
         src/sha512.cppm)
target_link_libraries(licrypto PUBLIC rstd.std)
