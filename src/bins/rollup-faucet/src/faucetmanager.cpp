#include "faucetmanager.h"
template <typename T>
std::string makeRequestMethod(const std::string& method, const T& params) {
  return json({
    {"jsonrpc", "2.0"},
    {"id", 1},
    {"method", method},
    {"params", params}
  }).dump();
}


namespace Faucet {

  std::string Manager::makeDripToAddress(const Address& address) {
    return makeRequestMethod("dripToAddress", json::array({address.hex(true).get()}));
  }

  void Manager::setup() {
    std::cout << "Setting up the faucet manager" << std::endl;
    std::cout << "Requesting nonces from the network" << std::endl;

    for (auto& worker : this->faucetWorkers_) {
      HTTPSyncClient client(this->httpEndpoint_.first.to_string(), std::to_string(this->httpEndpoint_.second));
      client.connect();
      auto response = client.makeHTTPRequest(makeRequestMethod("eth_getTransactionCount", json::array({worker.address.hex(true).get(), "latest"})));
      auto json = json::parse(response);
      if (json.contains("error")) {
        throw std::runtime_error("Error while getting nonce: " + response);
      }
      worker.nonce = Hex(json["result"].get<std::string>()).getUint();
    }
    std::cout << "Nonces received!" << std::endl;
  }

  void Manager::run() {
    std::cout << "Running faucet service..." << std::endl;
    this->server_.run();
  }


  std::string Manager::createTransactions(WorkerAccount& account,
                               const uint256_t& txNativeBalance,
                               const uint64_t& chainId,
                               const Address& to) {
      return makeRequestMethod("eth_sendRawTransaction",
          json::array({Hex::fromBytes(
            TxBlock(
              to,
              account.address,
              {},
              chainId,
              account.nonce,
              txNativeBalance,
              1000000000,
              1000000000,
              21000,
              account.privKey).rlpSerialize()
            ,true).forRPC()}));
  }

  void Manager::processDripToAddress(const Address& address) {
    // Firstly, lock the current state and check if existed, then grab the current worker account and move the index.
    try {
      {
        std::unique_lock lock(this->accountsMutex_);
        if (this->accounts_.contains(address)) {
          throw DynamicException("Address already dripped");
        }
        this->accounts_.insert(address);
      }
      Utils::safePrint("Dripping to address: " + address.hex(true).get());

      WorkerAccount* worker = nullptr;
      {
        std::lock_guard lock(this->lastIndexMutex_);
        Utils::safePrint("Dripping at index: " + std::to_string(this->lastIndex_));
        worker = &this->faucetWorkers_[this->lastIndex_];
        this->lastIndex_ = (this->lastIndex_ + 1) % this->faucetWorkers_.size();
      }
      // After getting the account, we can lock it and then use it for the drip operation.
      std::lock_guard lock(worker->inUse_);

      auto txRequest = createTransactions(*worker, 1000000000000000000, this->chainId_, address);
      HTTPSyncClient client(this->httpEndpoint_.first.to_string(), std::to_string(this->httpEndpoint_.second));
      client.connect();
      auto response = client.makeHTTPRequest(txRequest);
      auto json = json::parse(response);
      if (json.contains("error")) {
        throw std::runtime_error("Error while sending transactions: sent: " + txRequest + " received: " + json.dump());
      }
      /// Sleep for 3 seconds to allow the chain to move...
      std::this_thread::sleep_for(std::chrono::microseconds(500));
      std::pair<Hash, bool> txConfirm(Hex::toBytes(json["result"].get<std::string>()), false);
      while (txConfirm.second == false) {
        std::this_thread::sleep_for(std::chrono::microseconds(10));
        response = client.makeHTTPRequest(makeRequestMethod("eth_getTransactionReceipt", json::array({txConfirm.first.hex(true).get()})));
        json = json::parse(response);
        if (json.contains("error")) {
          throw std::runtime_error("Error while confirming transactions: sent: " + txRequest + " received: " + json.dump());
        }
        if (json["result"].is_null()) {
          continue;
        }
        Utils::safePrint("Transaction confirmed: " + txConfirm.first.hex(true).get());
        txConfirm.second = true;
      }
      worker->nonce++;

    } catch (std::exception& e) {
      std::unique_lock lock(this->accountsMutex_);
      this->accounts_.erase(address);
      Logger::logToDebug(LogType::ERROR, "FaucetManager", __func__,
        std::string("Error while processing dripToAddress: ") + e.what()
      );
    }

  }



  void Manager::dripToAddress(const Address& address) {
    this->threadPool_.push_task(&Manager::processDripToAddress, this, address);
  }
}