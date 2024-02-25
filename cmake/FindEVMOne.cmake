# Find the EVMOne library and define the following variables:
# EVMONE_FOUND
# EVMONE_INCLUDE_DIR
# EVMONE_LIBRARY

include(SelectLibraryConfigurations)
include(FindPackageHandleStandardArgs)

# Find path to EVMOne includes
find_path(EVMONE_INCLUDE_DIR NAMES evmone/evmone.h PATH_SUFFIXES /usr/local/include/)

# Find the EVMOne library file(s)
find_library(EVMONE_LIBRARY NAMES evmone.so.0.11 evmone.so.0.11.0 PATH_SUFFIXES /usr/local/lib/)

# Print out search paths for debugging
message(STATUS "Searching for EVMOne includes in: ${EVMONE_INCLUDE_DIR}")
message(STATUS "Searching for EVMOne library in: ${EVMONE_LIBRARY}")

# Check if EVMOne has been found
if(EVMONE_INCLUDE_DIR AND EVMONE_LIBRARY)
    set(EVMONE_FOUND TRUE)
endif()

# Provide feedback to the user
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
        EVMOne DEFAULT_MSG
        EVMONE_LIBRARY EVMONE_INCLUDE_DIR
)

# Print out debug information
message(STATUS "EVMONE_INCLUDE_DIR: ${EVMONE_INCLUDE_DIR}")
message(STATUS "EVMONE_LIBRARY: ${EVMONE_LIBRARY}")
message(STATUS "EVMONE_FOUND: ${EVMONE_FOUND}")

# Mark variables as advanced
mark_as_advanced(EVMONE_INCLUDE_DIR EVMONE_LIBRARY)