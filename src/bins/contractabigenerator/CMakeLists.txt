if(BUILD_AVALANCHEGO)
  # Compile and link the ABI generator executable
  add_executable(contractabigenerator "main.cpp")

  add_dependencies(contractabigenerator orbitersdk_lib)
  target_include_directories(contractabigenerator PRIVATE orbitersdk_lib ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(contractabigenerator
      orbitersdk_lib Speedb ${SNAPPY_LIBRARY} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
  )
else()
  # Compile and link the ABI generator executable
  add_executable(contractabigenerator "main.cpp")

  add_dependencies(contractabigenerator orbitersdk_lib)
  target_include_directories(contractabigenerator PRIVATE orbitersdk_lib ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(contractabigenerator
      orbitersdk_lib Speedb ${SNAPPY_LIBRARY} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Secp256k1 Ethash ${ETHASH_BYPRODUCTS}
  )
endif()