if(BUILD_AVALANCHEGO)

else()
    add_library(rollup_faucet_lib STATIC
            ${CMAKE_SOURCE_DIR}/src/bins/rollup-faucet/src/tmp.h
    )

    target_include_directories(rollup_faucet_lib PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} orbitersdk_lib)

    target_link_libraries(rollup_faucet_lib PRIVATE orbitersdk_lib
            ${CRYPTOPP_LIBRARIES} ${SCRYPT_LIBRARY} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
            Speedb ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} orbitersdk_lib
    )

    # Compile and link the rollup-faucet executable
    add_executable(rollup-faucet "main.cpp")

    add_dependencies(rollup-faucet orbitersdk_lib rollup_faucet_lib)
    target_include_directories(rollup-faucet PRIVATE orbitersdk_lib rollup_faucet_lib ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(rollup-faucet
            orbitersdk_lib rollup_faucet_lib Speedb ${SNAPPY_LIBRARY} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
    )
endif()