cmake_minimum_required(VERSION 3.20)
project(erebus VERSION 0.3.1 LANGUAGES CXX)

option(EREBUS_STATIC_CAPSTONE "Link Capstone statically (used for the self-contained app bundle)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(CAPSTONE IMPORTED_TARGET capstone)
endif()
if(NOT CAPSTONE_FOUND)
  # No pkg-config (or no capstone.pc): locate Capstone by hand. Set CAPSTONE_LIB / CAPSTONE_INCLUDE to override.
  find_library(CAPSTONE_LIB NAMES capstone libcapstone.a HINTS /opt/homebrew/lib /usr/local/lib REQUIRED)
  find_path(CAPSTONE_INCLUDE capstone/capstone.h HINTS /opt/homebrew/include /usr/local/include REQUIRED)
  add_library(PkgConfig::CAPSTONE INTERFACE IMPORTED)
  set_target_properties(PkgConfig::CAPSTONE PROPERTIES INTERFACE_LINK_LIBRARIES "${CAPSTONE_LIB}" INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE}")
endif()
find_package(SQLite3 REQUIRED)
find_path(CAPSTONE_ROOT_INC capstone/capstone.h HINTS /opt/homebrew/include /usr/local/include ${CAPSTONE_INCLUDE_DIRS}/.. ${CAPSTONE_INCLUDE})
find_path(HTTPLIB_INC httplib.h HINTS /opt/homebrew/include /usr/local/include REQUIRED)
find_path(NLOHMANN_INC nlohmann/json.hpp HINTS /opt/homebrew/include /usr/local/include REQUIRED)

file(READ ${CMAKE_SOURCE_DIR}/src/ui/index.html UI_INDEX_HTML)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/ui/index.html)
configure_file(${CMAKE_SOURCE_DIR}/src/ui/assets.cpp.in ${CMAKE_BINARY_DIR}/gen/assets.cpp @ONLY)

add_library(erebus_core STATIC
  src/core/image.cpp
  src/core/db.cpp
  src/core/asm.cpp
  src/core/swiftdemangle.cpp
  src/loaders/loader.cpp
  src/loaders/macho.cpp
  src/loaders/objc.cpp
  src/loaders/elf.cpp
  src/loaders/pe.cpp
  src/procs/proc.cpp
  src/analysis/analyzer.cpp
  src/cli/session.cpp
  src/cli/commands.cpp
  src/cli/render.cpp
  src/ui/server.cpp
  src/decomp/ir.cpp
  src/decomp/lifter.cpp
  src/decomp/lift_arm64.cpp
  src/decomp/lift_x86.cpp
  src/decomp/analysis.cpp
  src/decomp/decompile.cpp
  ${CMAKE_BINARY_DIR}/gen/assets.cpp
)
target_include_directories(erebus_core PUBLIC src ${CAPSTONE_ROOT_INC} ${HTTPLIB_INC} ${NLOHMANN_INC})
find_package(Threads REQUIRED)
target_link_libraries(erebus_core PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(erebus_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
if(EREBUS_STATIC_CAPSTONE)
  find_library(CAPSTONE_STATIC NAMES libcapstone.a HINTS /opt/homebrew/lib /usr/local/lib REQUIRED)
  target_link_libraries(erebus_core PUBLIC ${CAPSTONE_STATIC} SQLite::SQLite3)
else()
  target_link_libraries(erebus_core PUBLIC PkgConfig::CAPSTONE SQLite::SQLite3)
endif()

add_executable(erebus src/cli/main.cpp)
target_compile_definitions(erebus PRIVATE EREBUS_VERSION="${PROJECT_VERSION}")
target_link_libraries(erebus PRIVATE erebus_core)

install(TARGETS erebus RUNTIME DESTINATION bin)
