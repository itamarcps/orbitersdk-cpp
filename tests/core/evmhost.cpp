/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include "../../src/libs/catch2/catch_amalgamated.hpp"
#include "../../src/contract/templates/erc20.h"
#include "../../src/contract/abi.h"
#include "../../src/utils/db.h"
#include "../../src/utils/options.h"
#include "../../src/contract/contractmanager.h"
#include "../../src/core/rdpos.h"

#include "../sdktestsuite.hpp"

#include <filesystem>

// TODO: test events if/when implemented

namespace TERC20 {
  TEST_CASE("EVMOne Class", "[contract][evmone]") {
    SECTION("EVMOne AIO Test") {
      SDKTestSuite sdk = SDKTestSuite::createNewEnvironment("TestEVMOne ERC20");

    }
  }
}