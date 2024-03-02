#ifndef SIGNERMANAGER_H
#define SIGNERMANAGER_H

#include "net/http/httpclient.h"
#include "utils/utils.h"
#include "utils/tx.h"
#include "net/http/httpclient.h"
#include <boost/algorithm/string.hpp>
#include "libs/BS_thread_pool_light.hpp"
#include <shared_mutex>
#include <mutex>

struct WorkerAccount {
  const PrivKey privKey;
  const Address address;
  uint256_t nonce;
  explicit WorkerAccount (const PrivKey& privKey) : privKey(privKey), address(Secp256k1::toAddress(Secp256k1::toUPub(privKey))), nonce(0) {}
  // Copy constructor
  WorkerAccount(const WorkerAccount& other) : privKey(other.privKey), address(other.address), nonce(other.nonce) {}
};

class SignerManager {
  private:
    uint256_t latestBlock_;
    const Address contractAddress_;
    WorkerAccount signer_;
    const std::pair<net::ip::address_v4, uint16_t> httpEndpoint_;
    const uint64_t chainId_;
    HTTPSyncClient httpClient_;

    uint256_t requestLatestBlock();
    std::vector<std::tuple<uint256_t, Address, uint256_t>> requestEvents(const uint256_t& startBlock, const uint256_t& endBlock);
    // Make a new "send" tx. return json string eth_sendRawTransaction
    std::string createTransactions(WorkerAccount& account, const uint64_t& chainId,
                             const std::tuple<uint256_t, Address, uint256_t>& event);
  public:
    SignerManager(const Address& contractAddress, const PrivKey& signer, const std::pair<net::ip::address_v4, uint16_t>& httpEndpoint, const uint64_t& chainId, const uint256_t& latestBlock) :
  contractAddress_(contractAddress), signer_(signer), httpEndpoint_(httpEndpoint), chainId_(chainId), httpClient_(httpEndpoint.first.to_string(), std::to_string(httpEndpoint.second)), latestBlock_(latestBlock) {
      this->httpClient_.connect();
    }

    ~SignerManager() {
      this->httpClient_.close();
    }

    void setup();
    void run();


};

#endif // SIGNERMANAGER_H