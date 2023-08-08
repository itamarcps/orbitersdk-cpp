#include "options.h"

Options::Options(
  const std::string& rootPath, const std::string& web3clientVersion,
  const uint64_t& version, const uint64_t& chainID,
  const uint16_t& wsPort, const uint16_t& httpPort,
  const std::vector<std::pair<boost::asio::ip::address, uint64_t>>& discoveryNodes,
  const std::vector<Address>& genesisValidators
) : rootPath(rootPath), web3clientVersion(web3clientVersion),
  version(version), chainID(chainID), wsPort(wsPort),
  httpPort(httpPort), coinbase(Address()), isValidator(false), discoveryNodes(discoveryNodes), genesisValidators(genesisValidators)
{
  json options;
  if (std::filesystem::exists(rootPath + "/options.json")) return;
  options["rootPath"] = rootPath;
  options["web3clientVersion"] = web3clientVersion;
  options["version"] = version;
  options["chainID"] = chainID;
  options["wsPort"] = wsPort;
  options["httpPort"] = httpPort;
  options["discoveryNodes"] = json::array();
  for (const auto& [address, port] : discoveryNodes) {
    options["discoveryNodes"].push_back(json::object({
      {"address", address.to_string()},
      {"port", port}
    }));
  }
  options["genesisValidators"] = json::array();
  for (const auto& address : genesisValidators) {
    options["genesisValidators"].push_back(address.hex());
  }

  options["isValidator"] = isValidator;
  std::filesystem::create_directories(rootPath);
  std::ofstream o(rootPath + "/options.json");
  o << options.dump(2) << std::endl;
  o.close();
}

Options::Options(
  const std::string& rootPath, const std::string& web3clientVersion,
  const uint64_t& version, const uint64_t& chainID,
  const uint16_t& wsPort, const uint16_t& httpPort,
  const std::vector<std::pair<boost::asio::ip::address, uint64_t>>& discoveryNodes,
  const std::vector<Address>& genesisValidators,
  const PrivKey& privKey
) : rootPath(rootPath), web3clientVersion(web3clientVersion),
  version(version), chainID(chainID), wsPort(wsPort),
  httpPort(httpPort), discoveryNodes(discoveryNodes), coinbase(Secp256k1::toAddress(Secp256k1::toUPub(privKey))),
  genesisValidators(genesisValidators),
  isValidator(true)
{
  if (std::filesystem::exists(rootPath + "/options.json")) return;
  json options;
  options["rootPath"] = rootPath;
  options["web3clientVersion"] = web3clientVersion;
  options["version"] = version;
  options["chainID"] = chainID;
  options["wsPort"] = wsPort;
  options["httpPort"] = httpPort;
  options["discoveryNodes"] = json::array();
  for (const auto& [address, port] : discoveryNodes) {
    options["discoveryNodes"].push_back(json::object({
      {"address", address.to_string()},
      {"port", port}
    }));
  }
  options["genesisValidators"] = json::array();
  for (const auto& address : genesisValidators) {
    options["genesisValidators"].push_back(address.hex());
  }
  options["privKey"] = privKey.hex();
  std::filesystem::create_directories(rootPath);
  std::ofstream o(rootPath + "/options.json");
  o << options.dump(2) << std::endl;
  o.close();
}

const PrivKey Options::getValidatorPrivKey() const {
  json options;
  std::ifstream i(rootPath + "/options.json");
  i >> options;
  i.close();
  if (options.contains("privKey")) {
    const auto privKey = options["privKey"].get<std::string>();
    return PrivKey(Hex::toBytes(privKey));
  }
  return PrivKey();
}

Options Options::fromFile(const std::string& rootPath) {
  try {
    // Check if rootPath is valid
    if (!std::filesystem::exists(rootPath + "/options.json")) {
      std::filesystem::create_directory(rootPath);
      /// Defaults with 5 validators with the following addresses:
      /// This is done for testnet purposes.
      /// Validator1: Address: 0x7588b0f553d1910266089c58822e1120db47e572 PrivKey: 0xba5e6e9dd9cbd263969b94ee385d885c2d303dfc181db2a09f6bf19a7ba26759
      /// Validator2: Address: 0x5fb516dc2cfc1288e689ed377a9eebe2216cf1e3 PrivKey: 0x66ce71abe0b8acd92cfd3965d6f9d80122aed9b0e9bdd3dbe018230bafde5751
      /// Validator3: Address: 0x795083c42583842774febc21abb6df09e784fce5 PrivKey: 0x856aeb3b9c20a80d1520a2406875f405d336e09475f43c478eb4f0dafb765fe7
      /// Validator4: Address: 0xbec7b74f70c151707a0bfb20fe3767c6e65499e0 PrivKey: 0x81f288dd776f4edfe256d34af1f7d719f511559f19115af3e3d692e741faadc6
      /// Validator5: Address: 0xcabf34a268847a610287709d841e5cd590cc5c00 PrivKey: 0xfd84d99aa18b474bf383e10925d82194f1b0ca268e7a339032679d6e3a201ad4
      std::vector<Address> genesisValidatorList {
        Address(Hex::toBytes("0x7588b0f553d1910266089c58822e1120db47e572")),
        Address(Hex::toBytes("0x5fb516dc2cfc1288e689ed377a9eebe2216cf1e3")),
        Address(Hex::toBytes("0x795083c42583842774febc21abb6df09e784fce5")),
        Address(Hex::toBytes("0xbec7b74f70c151707a0bfb20fe3767c6e65499e0")),
        Address(Hex::toBytes("0xcabf34a268847a610287709d841e5cd590cc5c00"))
      };

      return Options(rootPath, "OrbiterSDK/cpp/linux_x86-64/0.1.2", 2, 8080, 8080, 8081, {}, genesisValidatorList);
    }

    std::ifstream i(rootPath + "/options.json");
    json options;
    i >> options;
    i.close();

    std::vector<std::pair<boost::asio::ip::address, uint64_t>> discoveryNodes;
    for (const auto& node : options["discoveryNodes"]) {
      discoveryNodes.push_back(std::make_pair(
        boost::asio::ip::address::from_string(node["address"].get<std::string>()),
        node["port"].get<uint64_t>()
      ));
    }

    std::vector<Address> genesisValidatorList;
    for (const auto& validator : options["genesisValidators"]) {
      genesisValidatorList.push_back(Address(Hex::toBytes(validator.get<std::string>())));
    }


    if (options.contains("privKey")) {
      const auto privKey = options["privKey"].get<std::string>();
      return Options(
        options["rootPath"].get<std::string>(),
        options["web3clientVersion"].get<std::string>(),
        options["version"].get<uint64_t>(),
        options["chainID"].get<uint64_t>(),
        options["wsPort"].get<uint64_t>(),
        options["httpPort"].get<uint64_t>(),
        discoveryNodes,
        genesisValidatorList,
        PrivKey(Hex::toBytes(privKey))
      );
    }

    return Options(
      options["rootPath"].get<std::string>(),
      options["web3clientVersion"].get<std::string>(),
      options["version"].get<uint64_t>(),
      options["chainID"].get<uint64_t>(),
      options["wsPort"].get<uint64_t>(),
      options["httpPort"].get<uint64_t>(),
      discoveryNodes,
      genesisValidatorList
    );
  } catch (std::exception &e) {
    std::cerr << "Could not create blockchain directory: " << e.what() << std::endl;
    throw "Could not create blockchain directory.";
  }
}

