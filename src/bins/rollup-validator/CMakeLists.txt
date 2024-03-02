if(BUILD_AVALANCHEGO)

else()
    add_library(rollup_validator_lib STATIC
            ${CMAKE_SOURCE_DIR}/src/bins/rollup-validator/src/signermanager.cpp
            ${CMAKE_SOURCE_DIR}/src/bins/rollup-validator/src/signermanager.h
    )

    target_include_directories(rollup_validator_lib PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} orbitersdk_lib)

    target_link_libraries(rollup_validator_lib PRIVATE orbitersdk_lib
            ${CRYPTOPP_LIBRARIES} ${SCRYPT_LIBRARY} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
            Speedb ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} orbitersdk_lib
    )

    # Compile and link the rollup-validator executable
    add_executable(rollup-validator "main.cpp")

    add_dependencies(rollup-validator orbitersdk_lib rollup_validator_lib)
    target_include_directories(rollup-validator PRIVATE orbitersdk_lib rollup_validator_lib ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(rollup-validator
            orbitersdk_lib rollup_validator_lib Speedb ${SNAPPY_LIBRARY} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
    )
endif()