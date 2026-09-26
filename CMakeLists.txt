cmake_minimum_required(VERSION 3.15)
project(ManualMapDetector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable warnings
if(MSVC)
    add_compile_options(/W4 /WX-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-cast-function-type)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/ConsoleUI.cpp
    src/ProcessScanner.cpp
    src/ModuleScanner.cpp
    src/MemoryScanner.cpp
    src/SignatureChecker.cpp
    src/PeDetector.cpp
)

# Headers
set(HEADERS
    src/ConsoleUI.h
    src/ProcessScanner.h
    src/ModuleScanner.h
    src/MemoryScanner.h
    src/SignatureChecker.h
    src/PeDetector.h
    src/HandleWrapper.h
)

# Create executable
add_executable(ManualMapDetector ${SOURCES} ${HEADERS})

# Link Windows libraries
target_link_libraries(ManualMapDetector PRIVATE
    psapi        # Process and module enumeration
    wintrust     # Authenticode signature verification
    crypt32      # Cryptographic functions
)

# Set output name
set_target_properties(ManualMapDetector PROPERTIES
    OUTPUT_NAME "ManualMapDetector"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Static linking for standalone exe (MinGW)
if(MINGW)
    target_link_options(ManualMapDetector PRIVATE -static -static-libgcc -static-libstdc++)
endif()
