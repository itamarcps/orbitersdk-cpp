/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include <iostream>
#include <filesystem>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include "src/core/evmhost.hpp"
#include <evmone/evmone.h>
#include "../../tests/sdktestsuite.hpp"
#include "../contract/templates/erc721mint.h"

#include "src/core/blockchain.h"

using namespace evmc::literals;

const auto FROM = 0x2000000000000000000000000000100000000003_address;
const auto ERC721 = 0x2000000000000000000000000000100000000004_address;

std::unique_ptr<Blockchain> blockchain = nullptr;

[[noreturn]] void signalHandler(int signum) {
  Logger::logToDebug(LogType::INFO, "MAIN", "MAIN", "Received signal " + std::to_string(signum) + ". Stopping the blockchain.");
  blockchain->stop();
  blockchain = nullptr; // Destroy the blockchain object, calling the destructor of every module and dumping to DB.
  Utils::safePrint("Exiting...");
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  exit(signum);
}

int main() {
  Utils::logToCout = true;

  std::cout << "Deploying ERC721Mint Contract" << std::endl;
  SDKTestSuite suite = SDKTestSuite::createNewEnvironment("benchmark");
  uint64_t iterations = 1000000;


  // std::tuple<const std::string &, const std::string &, const uint256_t&, const Address &, const std::string& >;
  auto erc721address = suite.deployContract<ERC721Mint>(std::string("ERC721"), std::string("ERC721"), uint256_t(10000000000), suite.getChainOwnerAccount().address, std::string(""));

  auto mint = suite.createNewTx(suite.getChainOwnerAccount(), erc721address, 0, Hex::toBytes("6a6278420000000000000000000000001a7fd0fecf205e04c5f95cd7939cf5b36da7fe3d"));

  std::cout << "Ready to start the mint benchmark!" << std::endl;

  std::cout << "Minting " << iterations << " tokens" << std::endl;
  Hash random(Utils::randBytes(32));
  RandomGen randGen(random);
  suite.setRandomGen(&randGen);
  auto start = std::chrono::high_resolution_clock::now();
  for (uint64_t i = 0; i < iterations; i++) {
    suite.callContract(mint, Hash(), 0);
  }
  auto end = std::chrono::high_resolution_clock::now();
  double durationInMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
  std::cout << "Minted " << iterations << " tokens in " << durationInMicroseconds / 1000000 << " seconds" << std::endl;
  std::cout << "Average microsecond per mint: " << durationInMicroseconds / iterations << std::endl;
  std::cout << "Average mint per second: " << iterations / (durationInMicroseconds / 1000000) << std::endl;

  return 0;
  std::string blockchainPath = std::filesystem::current_path().string() + std::string("/blockchain");
  blockchain = std::make_unique<Blockchain>(blockchainPath);
  // Start the blockchain syncing engine.
  std::signal(SIGINT, signalHandler);
  std::signal(SIGHUP, signalHandler);
  blockchain->start();
  std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::hours(std::numeric_limits<int>::max()));
  return 0;
}

