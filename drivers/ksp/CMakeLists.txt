cmake_minimum_required(VERSION 3.16)
project(OpenCertKSP C)

set(CMAKE_C_STANDARD 11)

# Windows only
if(NOT WIN32)
    message(FATAL_ERROR "OpenCert KSP is Windows-only")
endif()

# Source files
set(KSP_SOURCES
    opencert_ksp.c
)

# Build as DLL
add_library(OpenCertKSP SHARED ${KSP_SOURCES})

# Link Windows libraries
target_link_libraries(OpenCertKSP PRIVATE
    ncrypt
    bcrypt
    crypt32
)

# Export definition file
set_target_properties(OpenCertKSP PROPERTIES
    OUTPUT_NAME "OpenCertKSP"
    PREFIX ""
    SUFFIX ".dll"
)

# Generate .def file for exports
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/OpenCertKSP.def"
"LIBRARY OpenCertKSP\nEXPORTS\n    GetKeyStorageInterface\n")

target_sources(OpenCertKSP PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/OpenCertKSP.def"
)

# Install target
install(TARGETS OpenCertKSP
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Copy to setup directory after build
add_custom_command(TARGET OpenCertKSP POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:OpenCertKSP>
        "${CMAKE_SOURCE_DIR}/../setup/OpenCertKSP.dll"
    COMMENT "Copying OpenCertKSP.dll to setup directory"
)
