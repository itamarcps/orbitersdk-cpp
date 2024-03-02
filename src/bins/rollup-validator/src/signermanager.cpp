#include "signermanager.h"

#include "picojson.h"
#include "contract/abi.h"

template <typename T>
std::string makeRequestMethod(const std::string& method, const T& params) {
  return json({
    {"jsonrpc", "2.0"},
    {"id", 1},
    {"method", method},
    {"params", params}
  }).dump();
}



void SignerManager::setup() {

  // First, we need to know the current nonce of the account
  auto response = httpClient_.makeHTTPRequest(makeRequestMethod("eth_getTransactionCount", json::array({this->signer_.address.hex(true).get(), "latest"})));
  auto jsonResponse = json::parse(response);
  if (jsonResponse.contains("error")) {
    throw std::runtime_error("Error while getting nonce: " + response);
  }
  std::cout << "Got nonce!" << std::endl;
  this->signer_.nonce = Hex(jsonResponse["result"].get<std::string>()).getUint();
}

uint256_t SignerManager::requestLatestBlock() {
  auto response = httpClient_.makeHTTPRequest(makeRequestMethod("eth_blockNumber", json::array()));
  auto json = json::parse(response);
  if (json.contains("error")) {
    throw std::runtime_error("Error while getting latest block: " + response);
  }
  return Hex(json["result"].get<std::string>()).getUint();
}

Bytes createMessage (const uint256_t& tokenId, const Address& user, uint256_t rarity) {
  Bytes value;
  value.reserve(86); // 32 bytes for tokenId and 20 bytes for user
  Utils::appendBytes(value, Utils::uint256ToBytes(tokenId));
  Utils::appendBytes(value, user.asBytes());
  Utils::appendBytes(value, Utils::uint256ToBytes(rarity));
  return value;
}

Hash _toTyped32ByteDataHash (const Hash& messageHash) {
  Bytes value;
  value.insert(value.end(), 0x19);
  std::string ethereumSignedMessage = "Ethereum Signed Message:";
  Utils::appendBytes(value, ethereumSignedMessage);
  value.insert(value.end(), '\n');
  Utils::appendBytes(value, std::to_string(32));
  Utils::appendBytes(value, messageHash);
  std::cout << "_toTyped32ByteDataHash: " << Hex::fromBytes(value) << std::endl;
  return Utils::sha3(value);
}

std::string SignerManager::createTransactions(WorkerAccount& account,
                           const uint64_t& chainId,
                           const std::tuple<uint256_t, Address, uint256_t>& event) {

  const auto& [ tokenId, user, rarity ] = event;
  auto hash = Utils::sha3(createMessage(tokenId, user, rarity));
  auto messageHash = _toTyped32ByteDataHash(hash);
  auto signature = Secp256k1::sign(messageHash, account.privKey);
  const auto& r = signature.r();
  const auto& s = signature.s();
  auto v = signature.v();
  v += 27;
  Hash rHash(Utils::uint256ToBytes(r));
  Hash sHash(Utils::uint256ToBytes(s));

  Functor functor = ABI::FunctorEncoder::encode<uint256_t, uint8_t, Hash, Hash>("burn");
  Bytes data;
  Utils::appendBytes(data, functor);
  Utils::appendBytes(data, ABI::Encoder::encodeData<uint256_t, uint8_t, Hash, Hash>(tokenId, v, rHash, sHash));


  return makeRequestMethod("eth_sendRawTransaction",
      json::array({Hex::fromBytes(
        TxBlock(
          this->contractAddress_,
          account.address,
          data,
          chainId,
          account.nonce,
          0,
          1000000000,
          1000000000,
          210000,
          account.privKey).rlpSerialize()
        ,true).forRPC()}));
}

std::vector<  std::tuple<uint256_t, Address, uint256_t>  > SignerManager::requestEvents(const uint256_t& startBlock, const uint256_t& endBlock) {
  std::vector<std::tuple<uint256_t, Address, uint256_t>> events;
  auto response = httpClient_.makeHTTPRequest(makeRequestMethod("eth_getLogs", json::array({
    {
      {"fromBlock", Hex::fromBytes(Utils::uintToBytes(startBlock),true).forRPC()},
      {"toBlock", Hex::fromBytes(Utils::uintToBytes(endBlock),true).forRPC()},
      {"address", this->contractAddress_.hex(true).get()},
      {"topics", json::array({
        "0x9d3bd8ca6857d62b093fc756ed48d15bcccbe17031d64613798b025d9242623a"
        })}
    }
  })));
  json result = json::parse(response);
  if (result.contains("error")) {
    throw std::runtime_error("Error while getting events: " + response);
  }
  if (result["result"].empty()) {
    return events;
  }

  const auto& resultJsn = result["result"];
  uint64_t arrSize = resultJsn.size();
  std::cout << "arrSize: " << arrSize << std::endl;
  for (uint64_t i = 0; i < arrSize; i++) {
    std::tuple <uint256_t, Address, uint256_t> event;
    auto jsonval = json::parse(resultJsn.at(i).dump());
    std::string jsonStr = jsonval.dump();
    std::cout << "jsonStr: " << jsonStr << std::endl;
    picojson::value v;
    std::string err = picojson::parse(v, jsonStr);
    if (!err.empty()) {
      throw std::runtime_error("Error while parsing json: " + err);
    }

    // Dump it to see the structure
    std::string valStr = v.to_str();
    // As C++ is trolling us we need to manually extract the "data" from the serialized json
    // First, find where \"data\" is
    std::size_t found = valStr.find("\"data\"");
    // Then after that, find the ':'
    std::size_t found2 = valStr.find(":", found);
    // Now, find the next \" after the :
    std::size_t found3 = valStr.find("\"", found2);

    std::string data = valStr.substr(found3 + 1);
    /// Remove anything beyond the first " (including the " itself)
    data = data.substr(0, data.find("\""));
    std::cout << "data: " << data << std::endl;
    auto decodedData = ABI::Decoder::decodeData<uint256_t, Address, uint256_t>(Hex::toBytes(data));
    std::cout << "Got event!" << std::endl;
    std::get<0>(event) = std::get<0>(decodedData);
    std::get<1>(event) = std::get<1>(decodedData);
    std::get<2>(event) = std::get<2>(decodedData);
    std::cout << "tokenId: " << std::get<0>(event) << " owner: " << std::get<1>(event).hex(true).get() << std::endl;
    events.push_back(event);
  }
  return events;
}

void SignerManager::run() {
  bool log = true;
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // We need to request the events for every 1000 blocks (there is a limit of number of events in a request)
    uint256_t startBlock = this->latestBlock_;
    // Request the latest block from the network to know the latest block
    uint256_t latestBlock = SignerManager::requestLatestBlock();
    if (latestBlock == startBlock) {
      if (log) {
        std::cout << "No new blocks" << std::endl;
        log = false;
      }
      continue;
    }
    log = true;
    std::cout << "StartBlock: " << startBlock << " LatestBlock: " << latestBlock << std::endl;
    // If latestBlock is higher than startBlock + 1000, we need to request the events for every 1000 blocks
    if (latestBlock > startBlock + 1000) {
      latestBlock = startBlock + 1000;
      std::cout << "LatestBlock is higher than startBlock + 1000, requesting events for every 1000 blocks" << std::endl;
      std::cout << "Start block: " << startBlock << " Latest block: " << latestBlock << std::endl;
    }

    auto events = this->requestEvents(startBlock, latestBlock);
    this->latestBlock_ = latestBlock;
    std::vector<std::string> transactions_;
    std::vector<std::pair<Hash, bool>> sendTxHashes;
    for (const auto& event : events) {
      std::cout << "Got event!" << std::endl;
      std::cout << "tokenId: " << std::get<0>(event) << " owner: " << std::get<1>(event).hex(true).get() << std::endl;
      transactions_.push_back(this->createTransactions(this->signer_, this->chainId_, event));
      this->signer_.nonce++;
    }

    std::cout << "Sending: " << transactions_.size() << " transactions" << std::endl;
    for (auto& tx : transactions_) {
      std::this_thread::sleep_for(std::chrono::microseconds(3));
      auto response = this->httpClient_.makeHTTPRequest(tx);
      auto json = json::parse(response);
      if (json.contains("error")) {
        throw std::runtime_error("Error while sending transaction: " + response);
      }
      sendTxHashes.emplace_back(Hex::toBytes((json["result"].get<std::string>())), false);
    }

    std::cout << "Confirming: " << sendTxHashes.size() << " transactions" << std::endl;
    for (uint64_t i = 0; i < sendTxHashes.size(); ++i) {
      while (sendTxHashes[i].second == false) {
        std::this_thread::sleep_for(std::chrono::microseconds(3));
        auto response = this->httpClient_.makeHTTPRequest(makeRequestMethod("eth_getTransactionReceipt", json::array({sendTxHashes[i].first.hex(true).get()})));
        auto json = json::parse(response);
        if (json.contains("error")) {
          throw std::runtime_error("Error while confirming transaction: " + response);
        }
        if (json["result"].is_null()) {
          continue;
        }
        sendTxHashes[i].second = true;
      }
    }
  }
}