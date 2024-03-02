#include "src/signermanager.h"

#include <filesystem>
// In order to construct the signer manaer
// uint256_t latestBlock_;
// const Address contractAddress_;
// WorkerAccount signer_;
// const std::pair<net::ip::address_v4, uint16_t> httpEndpoint_;
// const uint64_t chainId_;
int main() {
  Utils::logToCout = true;
  uint256_t latestBlock_;
  Address contractAddress_;
  PrivKey signer_;
  std::pair<net::ip::address_v4, uint16_t> httpEndpoint_;
  uint64_t chainId_;


  std::cout << "Welcome to the Signer Manager, to continue, please type the contract address" << std::endl;
  std::string contractAddress;
  std::getline(std::cin, contractAddress);

  contractAddress_ = Address(Hex::toBytes(contractAddress));

  std::cout << "Please type the latest block height" << std::endl;
  std::string latestBlockStr;
  std::getline(std::cin, latestBlockStr);
  latestBlock_ = uint256_t(latestBlockStr);

  std::cout << "Please provide the chain Id (empty for default: 808080): " << std::endl;
  std::string chainIdStr;
  std::getline(std::cin, chainIdStr);

  if (chainIdStr.empty()) {
    chainId_ = 808080;
  } else {
    for (const auto& c : chainIdStr) {
      if (!std::isdigit(c)) {
        throw DynamicException("Invalid chain Id");
      }
    }
    chainId_ = std::stoull(chainIdStr);
  }

  std::cout << "Please provide the HTTP endpoint (IP:PORT) (empty for default: 127.0.0.1:8090): " << std::endl;
  std::string httpEndpointStr;
  std::getline(std::cin, httpEndpointStr);
  if (httpEndpointStr.empty()) {
    httpEndpoint_ = std::make_pair(net::ip::address_v4::from_string("127.0.0.1"), 8090);
  } else {
    std::vector<std::string> parts;
    boost::split(parts, httpEndpointStr, boost::is_any_of(":"));
    if (parts.size() != 2) {
      throw DynamicException("Invalid HTTP endpoint");
    }
    try {
      httpEndpoint_ = std::make_pair(net::ip::address_v4::from_string(parts[0]), std::stoul(parts[1]));
    } catch (const std::exception& e) {
      throw DynamicException("Invalid HTTP endpoint");
    }
  }

  std::cout << "Please type the signer private key, nothing for default: " << std::endl;;
  std::string signerPrivKey;
  std::getline(std::cin, signerPrivKey);

  if (!signerPrivKey.empty()) {
    static const std::regex hashFilter("^0x[0-9,a-f,A-F]{64}$");
    if (!std::regex_match(signerPrivKey, hashFilter)) {
      std::cout << "Invalid private key" << std::endl;
      return 1;
    }
    signer_ = PrivKey(Hex::toBytes(signerPrivKey));
  } else {
    signer_ = PrivKey(Hex::toBytes("0xaa"));
  }


  SignerManager manager(contractAddress_, signer_, httpEndpoint_, chainId_, latestBlock_);
  std::cout << "Manager setting up" << std::endl;
  manager.setup();
  std::cout << "Manager running" << std::endl;
  manager.run();




}
