#include "../../src/libs/catch2/catch_amalgamated.hpp"
#include "../../src/utils/options.h"
#include <filesystem>


namespace TOptions {
  TEST_CASE("Option Class", "[core][options]") {
    SECTION("Options from File (default)") {
      std::vector<Address> genesisValidatorList {
        Address(Hex::toBytes("0x7588b0f553d1910266089c58822e1120db47e572")),
        Address(Hex::toBytes("0x5fb516dc2cfc1288e689ed377a9eebe2216cf1e3")),
        Address(Hex::toBytes("0x795083c42583842774febc21abb6df09e784fce5")),
        Address(Hex::toBytes("0xbec7b74f70c151707a0bfb20fe3767c6e65499e0")),
        Address(Hex::toBytes("0xcabf34a268847a610287709d841e5cd590cc5c00"))
      };

      Block genesis(Hash(Utils::uint256ToBytes(0)), 0, 0);
      PrivKey genesisSigner(Hex::toBytes("0xe89ef6409c467285bcae9f80ab1cfeb3487cfe61ab28fb7d36443e1daa0c2867"));
      genesis.finalize(PrivKey(genesisSigner), 1656356646000000);

      std::vector<std::pair<Address, uint256_t>> genesisBalances {
        std::make_pair(Address(Hex::toBytes("0x00dead00665771855a34155f5e7405489df2c3c6")), uint256_t("1000000000000000000000"))
      };


      Options optionsWithPrivKey(
        "optionClassFromFileWithPrivKey",
        "OrbiterSDK/cpp/linux_x86-64/0.1.2",
        1,
        8080,
        8080,
        8081,
        {},
        genesisValidatorList,
        genesis,
        genesisSigner,
        genesisBalances,
        PrivKey(Hex::toBytes("0xb254f12b4ca3f0120f305cabf1188fe74f0bd38e58c932a3df79c4c55df8fa66"))
      );

      Options optionsFromFileWithPrivKey(Options::fromFile("optionClassFromFileWithPrivKey"));

      REQUIRE(optionsFromFileWithPrivKey.getRootPath() == optionsWithPrivKey.getRootPath());
      REQUIRE(optionsFromFileWithPrivKey.getSDKVersion() == optionsWithPrivKey.getSDKVersion());
      REQUIRE(optionsFromFileWithPrivKey.getWeb3ClientVersion() == optionsWithPrivKey.getWeb3ClientVersion());
      REQUIRE(optionsFromFileWithPrivKey.getVersion() == optionsWithPrivKey.getVersion());
      REQUIRE(optionsFromFileWithPrivKey.getChainID() == optionsWithPrivKey.getChainID());
      REQUIRE(optionsFromFileWithPrivKey.getP2PPort() == optionsWithPrivKey.getP2PPort());
      REQUIRE(optionsFromFileWithPrivKey.getHttpPort() == optionsWithPrivKey.getHttpPort());
      REQUIRE(optionsFromFileWithPrivKey.getCoinbase() == optionsWithPrivKey.getCoinbase());
      REQUIRE(optionsFromFileWithPrivKey.getValidatorPrivKey() == optionsWithPrivKey.getValidatorPrivKey());
      REQUIRE(optionsFromFileWithPrivKey.getGenesisValidators() == optionsWithPrivKey.getGenesisValidators());
      REQUIRE(optionsFromFileWithPrivKey.getGenesisBlock() == optionsWithPrivKey.getGenesisBlock());
      REQUIRE(optionsFromFileWithPrivKey.getGenesisBalances() == optionsWithPrivKey.getGenesisBalances());
    }
  }
}