/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#ifndef EVMHOST_HPP
#define EVMHOST_HPP

#include <evmc/evmc.hpp>
#include "../utils/utils.h"
#include "../utils/strings.h"
#include "../utils/hex.h"
#include "../utils/safehash.h"

#include "ecrecoverprecompile.hpp"
/**
 * EVM Abstraction for an account
 * An account holds nonce, code, codehash, balance and storage.
 * It always holds a "original" (first) and "current" (second) values
 * These original and current values are used in case of reversions due to contract exceptions
 */
struct EVMAccount {
  std::pair<uint64_t, uint64_t> nonce;  ///< Account nonce.
  std::pair<Bytes, Bytes> code;         ///< Account code.
  std::pair<Hash, Hash> codeHash;       ///< Account code hash.
  std::pair<uint256_t, uint256_t> balance;  ///< Account balance.
  std::unordered_map<Hash, std::pair<Hash, Hash>, SafeHash> storage;  ///< Account storage.
  std::unordered_map<Hash, Hash, SafeHash> transientStorage; ///< Account transient storage.
};


/*
 * Class for the EVMHost
 * used by the State to execute the EVM
 * Everything is public as we want the State to be able to access everything
 */

class EVMHost : public evmc::Host {
  public:
    EVMHost(evmc_vm* vm) : vm{vm} {}
    evmc_vm* vm;

    std::unordered_map<Address, EVMAccount, SafeHash> accounts;
    std::vector<Address> accessedAccounts;                   // Used to know what accounts were accessed to commit or revert
    std::vector<std::pair<Address, Hash>> accessedStorages;  // Used to know what storages were accessed to commit or reverts
    std::vector<Address> accessedTransients;                 // Used to know what transient storages were accessed to clear
    evmc_tx_context currentTxContext = {};                   // Current transaction context
    std::vector<std::array<uint8_t, 32>> m_ecrecover_results; // Used to store the results of ecrecover precompile (so we don't have a memory leak)
    mutable bool shouldRevert = false;                               // Used to know if we should revert or commit in the case of a exception inside any of the calls below

    bool account_exists(const evmc::address& addr) const noexcept override {
      try {
        Address address(addr);
        return this->accounts.find(address) != this->accounts.end();
      } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return false;
      }
    }
    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
      try {
        const auto acc = this->accounts.find(addr);
        if (acc == this->accounts.end()) {
          return {};
        }
        const auto storage = acc->second.storage.find(key);
        if (storage == acc->second.storage.end()) {
          return {};
        }
        return storage->second.second.toEvmcBytes32();
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return {};
      }
    }

    evmc_storage_status set_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value) noexcept override {
      auto& oldVal = this->accounts[addr].storage[key];

      try {
        this->accessedStorages.emplace_back(addr, key);
        // bytes32 is an array of uint8_t bytes[32];, Hash .raw() returns a pointer to the start of a std::array<uint8_t, 32>
        // We can can the pointer to a bytes32
        const evmc::bytes32* oldOrig = reinterpret_cast<const evmc::bytes32*>(oldVal.first.raw());
        evmc::bytes32* oldCurr = reinterpret_cast<evmc::bytes32*>(oldVal.second.raw_non_const());

        // Folow EIP-1283
        if (*oldCurr == value) {
          return evmc_storage_status::EVMC_STORAGE_ASSIGNED;
        }

        evmc_storage_status status{};
        if (oldOrig == oldCurr) {
          if (!oldCurr) {
            status = evmc_storage_status::EVMC_STORAGE_ADDED;
          } else if (value) {
            status = evmc_storage_status::EVMC_STORAGE_MODIFIED;
          } else {
            status = evmc_storage_status::EVMC_STORAGE_DELETED;
          }
        } else {
          status = evmc_storage_status::EVMC_STORAGE_ASSIGNED;
        }

        *oldCurr = value;
        return status;
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return evmc_storage_status::EVMC_STORAGE_MODIFIED;
      }
    }

    evmc::uint256be get_balance(const evmc::address& addr) const noexcept override {
      try {
        const auto acc = this->accounts.find(addr);
        if (acc == this->accounts.end()) {
          return {};
        }
        return Utils::uint256ToEvmcUint256(acc->second.balance.second);
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return {};
      }
    }

    size_t get_code_size(const evmc::address& addr) const noexcept override {
      try {
        const auto acc = this->accounts.find(addr);
        if (acc == this->accounts.end()) {
          return 0;
        }
        return acc->second.code.second.size();
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return 0;
      }
    }

    evmc::bytes32 get_code_hash(const evmc::address& addr) const noexcept override {
      try {
        const auto acc = this->accounts.find(addr);
        if (acc == this->accounts.end()) {
          return {};
        }
        return acc->second.codeHash.second.toEvmcBytes32();
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return {};
      }
    }

    size_t copy_code(const evmc::address& addr, size_t code_offset, uint8_t* buffer_data, size_t buffer_size) const noexcept override {
      try {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
          return 0;

        const auto& code = it->second.code.second;

        if (code_offset >= code.size())
          return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
          std::copy_n(&code[code_offset], n, buffer_data);

        return n;
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return 0;
      }
    }
    bool selfdestruct(const evmc::address& addr, const evmc::address& beneficiary) noexcept override {
      // SelfDestruct is NOT implemented/allowed in Sparq
      this->shouldRevert = true;
      return false;
    }

    evmc::Result call(const evmc_message& msg) noexcept override {
      std::cout << "CALL IS CALLED!!!" << std::endl;
      if (msg.recipient == ECRECOVER_ADDRESS) {
        return Precompile::ecrecover(msg, m_ecrecover_results);
      }

      evmc::Result result (evmc_execute(this->vm, &this->get_interface(), (evmc_host_context*)this,
               evmc_revision::EVMC_LATEST_STABLE_REVISION, &msg,
               accounts[msg.recipient].code.second.data(), accounts[msg.recipient].code.second.size()));
      return result;
    }

    evmc_tx_context get_tx_context() const noexcept override {
      return this->currentTxContext;
    }

    evmc::bytes32 get_block_hash(int64_t number) const noexcept override {
      // TODO: Implement after integrating with state
      return {};
    }

    void emit_log(const evmc::address& addr, const uint8_t* data, size_t data_size, const evmc::bytes32 topics[], size_t topics_count) noexcept override {
      // TODO: Implement after integrating with state
    }

    evmc_access_status access_account(const evmc::address& addr) noexcept override {
      // Always tell the EVM we are accessing in a warm manner
      return EVMC_ACCESS_WARM;
    }

    evmc_access_status access_storage(const evmc::address& addr, const evmc::bytes32& key) noexcept override {
      // Like before, always tell the EVM we are accessing in a warm manner
      return EVMC_ACCESS_WARM;
    }

    evmc::bytes32 get_transient_storage(const evmc::address &addr, const evmc::bytes32 &key) const noexcept override {
      try {
        const auto acc = this->accounts.find(addr);
        if (acc == this->accounts.end()) {
          return {};
        }
        const auto storage = acc->second.transientStorage.find(key);
        if (storage == acc->second.transientStorage.end()) {
          return {};
        }
        return storage->second.toEvmcBytes32();
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return {};
      }
    }

    void set_transient_storage(const evmc::address &addr, const evmc::bytes32 &key, const evmc::bytes32 &value) noexcept override {
      try {
        this->accessedTransients.push_back(addr);
        this->accounts[addr].transientStorage[key] = Hash(value);
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
      }
    }

    void setBalance(const Address& address, const uint256_t& balance) {
      this->accounts[address].balance.second = balance;
    }

    void commit() {
      // TODO: Use internal variables to commit the state
      for (const auto& [addr, key] : this->accessedStorages) {
        this->accounts[addr].storage[key].first = this->accounts[addr].storage[key].second;
      }
      for (const auto& account : this->accessedAccounts) {
        auto& acc = this->accounts[account];
        acc.nonce.first = this->accounts[account].nonce.second;
        acc.balance.first = this->accounts[account].balance.second;
        acc.code.first = this->accounts[account].code.second;
        acc.codeHash.first = this->accounts[account].codeHash.second;
      }
      for (const auto& addr : this->accessedTransients) {
        this->accounts[addr].transientStorage.clear();
      }
      m_ecrecover_results.clear();
    }

    void revert() {
      // TODO: Use internal variables to revert the state
      for (const auto& [addr, key] : this->accessedStorages) {
        this->accounts[addr].storage[key].second = this->accounts[addr].storage[key].first;
      }
      for (const auto& account : this->accessedAccounts) {
        auto& acc = this->accounts[account];
        acc.nonce.second = this->accounts[account].nonce.first;
        acc.balance.second = this->accounts[account].balance.first;
        acc.code.second = this->accounts[account].code.first;
        acc.codeHash.second = this->accounts[account].codeHash.first;
      }
      for (const auto& addr : this->accessedTransients) {
        this ->accounts[addr].transientStorage.clear();
      }
    }
};


#endif // EVMHOST_HPP