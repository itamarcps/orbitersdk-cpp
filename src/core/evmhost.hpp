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
    evmc_tx_context currentTxContext = {};                   // Current transaction context
    mutable bool shouldRevert = false;                               // Used to know if we should revert or commit in the case of a exception inside any of the calls below

    bool account_exists(const evmc::address& addr) const noexcept override {
      try {
        Address address(addr);
        return accounts.find(address) != accounts.end();
      } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        this->shouldRevert = true;
        return false;
      }
    }
    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
      try {
        const auto acc = accounts.find(addr);
        if (acc == accounts.end()) {
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
    evmc_storage_status set_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value) noexcept override;
    evmc::uint256be get_balance(const evmc::address& addr) const noexcept override;
    size_t get_code_size(const evmc::address& addr) const noexcept override;
    evmc::bytes32 get_code_hash(const evmc::address& addr) const noexcept override;
    size_t copy_code(const evmc::address& addr, size_t code_offset, uint8_t* buffer_data, size_t buffer_size) const noexcept override;
    bool selfdestruct(const evmc::address& addr, const evmc::address& beneficiary) noexcept override;
    evmc::Result call(const evmc_message& msg) noexcept override;
    evmc_tx_context get_tx_context() const noexcept override;
    evmc::bytes32 get_block_hash(int64_t number) const noexcept override;
    void emit_log(const evmc::address& addr, const uint8_t* data, size_t data_size, const evmc::bytes32 topics[], size_t topics_count) noexcept override;
    evmc_access_status access_account(const evmc::address& addr) noexcept override;
    evmc_access_status access_storage(const evmc::address& addr, const evmc::bytes32& key) noexcept override;
    evmc::bytes32 get_transient_storage(const evmc::address &addr, const evmc::bytes32 &key) const noexcept override;
    void set_transient_storage(const evmc::address &addr, const evmc::bytes32 &key, const evmc::bytes32 &value) noexcept override;


    void commit();
    void revert();
};


#endif // EVMHOST_HPP