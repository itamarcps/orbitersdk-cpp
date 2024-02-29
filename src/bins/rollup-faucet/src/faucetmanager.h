#ifndef FAUCETMANAGER_H
#define FAUCETMANAGER_H

#include "httpserver.h"
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
  std::mutex inUse_;
  explicit WorkerAccount (const PrivKey& privKey) : privKey(privKey), address(Secp256k1::toAddress(Secp256k1::toUPub(privKey))), nonce(0) {}
  // Copy constructor
  WorkerAccount(const WorkerAccount& other) : privKey(other.privKey), address(other.address), nonce(other.nonce) {}
};

namespace Faucet {
  class Manager {
    private:
      BS::thread_pool_light threadPool_;
      std::vector<WorkerAccount> faucetWorkers_;
      const uint64_t chainId_;
      HTTPServer server_;
      const std::pair<net::ip::address_v4, uint16_t> httpEndpoint_;  // HTTP endpoint to be used for the client
      const uint16_t port_; // Port to be used for the server
      std::mutex lastIndexMutex_;
      uint64_t lastIndex_ = 0;
      uint64_t httpServerIndex_ = 0;
      std::shared_mutex accountsMutex_;
      std::unordered_set<Address, SafeHash> accounts_;
      std::vector<HTTPSyncClient> clients_;
    public:

      Manager(
        const std::vector<WorkerAccount>& faucetWorkers,
        const uint64_t& chainId,
        const std::pair<net::ip::address_v4, uint16_t>& httpEndpoint,
        const uint16_t& port
      ) : faucetWorkers_(faucetWorkers), chainId_(chainId), httpEndpoint_(httpEndpoint), port_(port), server_(port, *this), threadPool_(2048) {}

      Manager(const Manager& other) = delete;
      Manager& operator=(const Manager& other) = delete;
      Manager(Manager&& other) = delete;
      Manager& operator=(Manager&& other) = delete;

      static std::string makeDripToAddress(const Address& address);

      // Make a new "send" tx. return json string eth_sendRawTransaction
      static std::string createTransactions(WorkerAccount& account,
                                 const uint256_t& txNativeBalance,
                                 const uint64_t& chainId,
                                 const Address& to);


      void setup();
      void run();
      void processDripToAddress(const Address& address);

      void dripToAddress(const Address& address);
  };
};

#endif  // FAUCETMANAGER_H
