# Find the Evmc library and define the following variables:
# EVMC_FOUND
# EVMC_INCLUDE_DIR
# EVMC_LIBRARY

include(SelectLibraryConfigurations)
include(FindPackageHandleStandardArgs)

find_path(EVMC_INCLUDE_DIR NAMES evmc/evmc.h PATH_SUFFIXES /usr/local/include/)
find_library(EVMC_INSTRUCTIONS_LIBRARY NAMES libevmc-instructions.a PATH_SUFFIXES /usr/local/lib/)
find_library(EVMC_LOADER_LIBRARY NAMES libevmc-loader.a PATH_SUFFIXES /usr/local/lib/)
find_library(EVMC_TOOLING_LIBRARY NAMES libtooling.a PATH_SUFFIXES /usr/local/lib/)

set(EVMC_LIBRARY ${EVMC_INSTRUCTIONS_LIBRARY} ${EVMC_LOADER_LIBRARY} ${EVMC_TOOLING_LIBRARY})

SELECT_LIBRARY_CONFIGURATIONS(Evmc)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(
        Evmc DEFAULT_MSG
        EVMC_LIBRARY EVMC_INCLUDE_DIR
)

mark_as_advanced(EVMC_INCLUDE_DIR EVMC_LIBRARY)