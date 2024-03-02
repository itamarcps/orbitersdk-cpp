/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include "state.h"
#include <evmone/evmone.h>

State::State(
  DB& db,
  Storage& storage,
  P2P::ManagerNormal& p2pManager,
  const Options& options
) : db_(db), storage_(storage), p2pManager_(p2pManager), options_(options),
rdpos_(db, storage, p2pManager, options, *this),
contractManager_(db, *this, rdpos_, options), vm_(evmc_create_evmone()), evmHost_(&this->storage_, &this->db_, &this->options_, this->vm_)
{
  std::unique_lock lock(this->stateMutex_);
  auto accountsFromDB = db_.getBatch(DBPrefix::nativeAccounts);
  if (accountsFromDB.empty()) {
    for (const auto& [account, balance] : options_.getGenesisBalances()) {
      // Initialize all accounts within options genesis balances.
      Bytes value;
      Utils::appendBytes(value, Utils::uint256ToBytes(balance));
      Utils::appendBytes(value, Utils::uint64ToBytes(0));
      db_.put(account.get(), value, DBPrefix::nativeAccounts);
    }
    accountsFromDB = db_.getBatch(DBPrefix::nativeAccounts);
  }

  for (const auto& dbEntry : accountsFromDB) {
    BytesArrView data(dbEntry.value);
    uint256_t balance = Utils::bytesToUint256(data.subspan(0,32));
    uint64_t nonce = Utils::bytesToUint64(data.subspan(32));

    this->evmHost_.accounts[Address(dbEntry.key)].balance.first = this->evmHost_.accounts[Address(dbEntry.key)].balance.second = balance;
    this->evmHost_.accounts[Address(dbEntry.key)].nonce.first = this->evmHost_.accounts[Address(dbEntry.key)].nonce.second = nonce;
  }
  auto latestBlock = this->storage_.latest();
  this->contractManager_.updateContractGlobals(Secp256k1::toAddress(latestBlock->getValidatorPubKey()), latestBlock->hash(), latestBlock->getNHeight(), latestBlock->getTimestamp());
  this->evmHost_.commitBalance();
  this->evmHost_.commitNonce();
  this->currentRandomGen_ = std::make_unique<RandomGen>(latestBlock->getBlockRandomness());
  this->contractManager_.updateRandomGen(this->currentRandomGen_.get());
}

State::~State() {
  // DB is stored as following
  // Under the DBPrefix::nativeAccounts
  // Each key == Address
  // Each Value == uint256_t + uint256
  DBBatch accountsBatch;
  std::unique_lock lock(this->stateMutex_);
  evmc_destroy(this->vm_);
  // Delete the vm_ pointer as it is no longer needed.
  for (const auto& [address, account] : this->evmHost_.accounts) {
    Bytes serializedBytes;
    Utils::appendBytes(serializedBytes, Utils::uint256ToBytes(account.balance.second));
    Utils::appendBytes(serializedBytes, Utils::uint64ToBytes(account.nonce.second));
    accountsBatch.push_back(address.get(), serializedBytes, DBPrefix::nativeAccounts);
  }

  this->db_.putBatch(accountsBatch);
}

TxInvalid State::validateTransactionInternal(const TxBlock& tx) const {
  /**
   * Rules for a transaction to be accepted within the current state:
   * Transaction value + txFee (gas * gasPrice) needs to be lower than account balance
   * Transaction nonce must match account nonce
   */

  // Verify if transaction already exists within the mempool, if on mempool, it has been validated previously.
  if (this->mempool_.contains(tx.hash())) {
    //Logger::logToDebug(LogType::INFO, Log::state, __func__, "Transaction: " + tx.hash().hex().get() + " already in mempool");
    return TxInvalid::NotInvalid;
  }
  auto accountIt = this->evmHost_.accounts.find(tx.getFrom());
  if (accountIt == this->evmHost_.accounts.end()) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__, "Account " + tx.getFrom().hex(true).get() + "doesn't exist (0 balance and 0 nonce)");
    auto to = tx.getTo();
    auto v = tx.getV();
    auto r = tx.getR();
    auto s = tx.getS();
    // LogtoDebug to v r s
      Logger::logToDebug(LogType::ERROR, Log::state, __func__, "v: " + std::to_string(v) + " r: " + Hex::fromBytes(Utils::uint256ToBytes(r) , true).get() + " s: " + Hex::fromBytes(Utils::uint256ToBytes(s) , true).get());
      Logger::logToDebug( LogType::ERROR, Log::state, __func__, "to: " + to.hex(true).get());
    return TxInvalid::InvalidBalance;
  }
  const auto& accBalance = accountIt->second.balance.second;
  const auto& accNonce = accountIt->second.nonce.second;
  uint256_t txWithFees = tx.getValue() + (tx.getGasLimit() * tx.getMaxFeePerGas());
  if (txWithFees > accBalance) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__,
                      "Transaction sender: " + tx.getFrom().hex().get() + " doesn't have balance to send transaction"
                      + " expected: " + txWithFees.str() + " has: " + accBalance.str());
    return TxInvalid::InvalidBalance;
  }
  // TODO: The blockchain is able to store higher nonce transactions until they are valid. Handle this case.
  if (accNonce != tx.getNonce()) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__, "Transaction: " + tx.hash().hex().get() + " nonce mismatch, expected: " + std::to_string(accNonce)
                                            + " got: " + tx.getNonce().str());
    return TxInvalid::InvalidNonce;
  }
  return TxInvalid::NotInvalid;
}

void State::processTransaction(const TxBlock& tx, const Hash& blockHash, const uint64_t& blockHeight,
                 const Address& blockCoinbase,
                 const uint64_t& blockTimestamp,
                 const uint64_t& blockGasLimit,
                 const uint256_t& chainId, const uint64_t& txIndex) {
  // Lock is already called by processNextBlock.
  // processNextBlock already calls validateTransaction in every tx,
  // as it calls validateNextBlock as a sanity check.
  auto& toAccountIt = this->evmHost_.accounts[tx.getTo()];
  auto accountIt = this->evmHost_.accounts.find(tx.getFrom());
  auto& toBalance = toAccountIt.balance.second;
  auto& balance = accountIt->second.balance.second;
  auto& nonce = accountIt->second.nonce.second;
  this->evmHost_.accessedAccountsBalances.emplace_back(tx.getFrom());
  this->evmHost_.accessedAccountsNonces.emplace_back(tx.getFrom());
  if (this->evmHost_.isEvmContract(tx.getTo()) || tx.getTo() == Address()) {
    // EVM Call! Set the tx context and then call the contract.
    // First, try transfering the balance!
    this->evmHost_.accessedAccountsBalances.emplace_back(tx.getFrom());
    Address realTo = (tx.getTo() == Address()) ? this->evmHost_.deriveContractAddress(tx.getNonce(), tx.getFrom()) : tx.getTo();
    if (tx.getValue()) {
      this->evmHost_.accounts[realTo].balance.second += tx.getValue();
      balance -= tx.getValue();
      this->evmHost_.accessedAccountsBalances.emplace_back(tx.getTo());
    }
    // Then set context
    try {
      this->evmHost_.setTxContext(tx.txToCallInfo(), blockHash, blockHeight, blockCoinbase, blockTimestamp, blockGasLimit, chainId);
      this->evmHost_.currentTxHash = tx.hash();
      auto evmCallResult = this->evmHost_.execute(tx.txToCallInfo(), this->currentRandomGen_.get());
      int64_t gasLeft = evmCallResult.gas_left;
      gasLeft - 21000;
      if (gasLeft < 0) {
        throw DynamicException("Error when executing EVM contract, gas limit is lower than gas left");
      }
      uint256_t gasUsed = tx.getGasLimit() - uint256_t(gasLeft);
      balance -= gasUsed * tx.getMaxFeePerGas();
      if (evmCallResult.status_code || this->evmHost_.shouldRevert) {
        std::cout << "should revert: " << this->evmHost_.shouldRevert << std::endl;
        throw DynamicException("Error when executing EVM contract, evmCallResult.status_code: " + std::string(evmc_status_code_to_string(evmCallResult.status_code)) + " bytes: " + Hex::fromBytes(Utils::cArrayToBytes(evmCallResult.output_data, evmCallResult.output_size)).get());
      }

      // After running and everything ok but before committing, we need to register the events
      {
        for (uint64_t i = 0; i < this->evmHost_.emittedEvents.size(); i++) {
          const auto& emittedEvent = this->evmHost_.emittedEvents[i];
          Event sdkEvent = Event(
            "",
            i,
            tx.hash(),
            txIndex,
            blockHash,
            blockHeight,
            emittedEvent.creator,
            emittedEvent.data,
            emittedEvent.topics,
            false
          );
          this->contractManager_.commitEvent(std::move(sdkEvent));
        }
      }
      this->evmHost_.commit();
      this->evmHost_.commitCode();
    } catch (const std::exception& e) {
      Logger::logToDebug(LogType::ERROR, Log::state, __func__,
        "Transaction: " + tx.hash().hex().get() + " failed to process, reason: " + e.what()
      );
      this->evmHost_.shouldRevert = false;
      // Tx went badly, revert the changes.
      balance += tx.getValue();
      this->evmHost_.accounts[realTo].balance.second -= tx.getValue();
      this->evmHost_.revert();
      this->evmHost_.revertCode();
    }
  } else {
    /// Classic OrbiterSDK transaction
    try {
      uint256_t txValueWithFees = tx.getValue() + (
        tx.getGasLimit() * tx.getMaxFeePerGas()
      ); // This needs to change with payable contract functions
      balance -= txValueWithFees;
      toBalance += tx.getValue();
      if (this->contractManager_.isContractCall(tx)) {
        Utils::safePrint(std::string("Processing transaction call txid: ") + tx.hash().hex().get());
        if (this->contractManager_.isPayable(tx.txToCallInfo())) this->processingPayable_ = true;
        this->contractManager_.callContract(tx, blockHash, txIndex);
        this->processingPayable_ = false;
      }
      // We need to take note of the accessed accounts in other to call commit() or revert() on them to update nonce/balance.
      this->evmHost_.accessedAccountsBalances.emplace_back(tx.getTo());
      this->evmHost_.commit();
    } catch (const std::exception& e) {
      Logger::logToDebug(LogType::ERROR, Log::state, __func__,
        "Transaction: " + tx.hash().hex().get() + " failed to process, reason: " + e.what()
      );
      if(this->processingPayable_) {
        balance += tx.getValue();
        toBalance -= tx.getValue();
        this->processingPayable_ = false;
      }
      balance += tx.getValue();
    }
  }
  nonce++;
  this->evmHost_.accessedAccountsNonces.emplace_back(tx.getFrom());
  this->evmHost_.commitNonce();
  this->evmHost_.commitBalance();
}

void State::refreshMempool(const Block& block) {
  // No need to lock mutex as function caller (this->processNextBlock) already lock mutex.
  // Remove all transactions within the block that exists on the unordered_map.
  for (const auto& tx : block.getTxs()) {
    const auto it = this->mempool_.find(tx.hash());
    if (it != this->mempool_.end()) {
      this->mempool_.erase(it);
    }
  }

  // Copy mempool over
  auto mempoolCopy = this->mempool_;
  this->mempool_.clear();

  // Verify if the transactions within the old mempool
  // not added to the block are valid given the current state
  for (const auto& [hash, tx] : mempoolCopy) {
    // Calls internal function which doesn't lock mutex.
    if (!this->validateTransactionInternal(tx)) {
      this->mempool_.insert({hash, tx});
    }
  }
}

uint256_t State::getNativeBalance(const Address &addr) const {
  std::shared_lock lock(this->stateMutex_);
  auto it = this->evmHost_.accounts.find(addr);
  if (it == this->evmHost_.accounts.end()) return 0;
  return it->second.balance.second;
}

uint64_t State::getNativeNonce(const Address& addr) const {
  std::shared_lock lock(this->stateMutex_);
  auto it = this->evmHost_.accounts.find(addr);
  if (it == this->evmHost_.accounts.end()) return 0;
  return it->second.nonce.second;
}

// std::unordered_map<Address, Account, SafeHash> State::getAccounts() const {
//   std::shared_lock lock(this->stateMutex_);
//   return this->evmHost_.accounts;
// }

std::unordered_map<Hash, TxBlock, SafeHash> State::getMempool() const {
  std::shared_lock lock(this->stateMutex_);
  return this->mempool_;
}

bool State::validateNextBlock(const Block& block) const {
  /**
   * Rules for a block to be accepted within the current state
   * Block nHeight must match latest nHeight + 1
   * Block nPrevHash must match latest hash
   * Block nTimestamp must be higher than latest block
   * Block has valid rdPoS transaction and signature based on current state.
   * All transactions within Block are valid (does not return false on validateTransaction)
   * Block constructor already checks if merkle roots within a block are valid.
   */
  auto latestBlock = this->storage_.latest();
  if (block.getNHeight() != latestBlock->getNHeight() + 1) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__,
      "Block nHeight doesn't match, expected " + std::to_string(latestBlock->getNHeight() + 1)
      + " got " + std::to_string(block.getNHeight())
    );
    return false;
  }

  if (block.getPrevBlockHash() != latestBlock->hash()) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__,
      "Block prevBlockHash doesn't match, expected " + latestBlock->hash().hex().get()
      + " got: " + block.getPrevBlockHash().hex().get()
    );
    return false;
  }

  if (latestBlock->getTimestamp() > block.getTimestamp()) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__,
      "Block timestamp is lower than latest block, expected higher than "
      + std::to_string(latestBlock->getTimestamp()) + " got " + std::to_string(block.getTimestamp())
    );
    return false;
  }

  if (!this->rdpos_.validateBlock(block)) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__, "Invalid rdPoS in block");
    return false;
  }

  std::shared_lock verifyingBlockTxs(this->stateMutex_);
  for (const auto& tx : block.getTxs()) {
    if (this->validateTransactionInternal(tx)) {
      Logger::logToDebug(LogType::ERROR, Log::state, __func__,
        "Transaction " + tx.hash().hex().get() + " within block is invalid"
      );
      return false;
    }
  }

  Logger::logToDebug(LogType::INFO, Log::state, __func__,
    "Block " + block.hash().hex().get() + " is valid. (Sanity Check Passed)"
  );
  return true;
}

void State::processNextBlock(Block&& block) {
  // Sanity check - if it passes, the block is valid and will be processed
  if (!this->validateNextBlock(block)) {
    Logger::logToDebug(LogType::ERROR, Log::state, __func__,
      "Sanity check failed - blockchain is trying to append a invalid block, throwing"
    );
    throw DynamicException("Invalid block detected during processNextBlock sanity check");
  }

  std::unique_lock lock(this->stateMutex_);

  // Update contract globals based on (now) latest block
  const Hash blockHash = block.hash();
  this->contractManager_.updateContractGlobals(Secp256k1::toAddress(block.getValidatorPubKey()), blockHash, block.getNHeight(), block.getTimestamp());
  this->currentRandomGen_ = std::make_unique<RandomGen>(block.getBlockRandomness());
  this->contractManager_.updateRandomGen(this->currentRandomGen_.get());

  // Process transactions of the block within the current state
  uint64_t txIndex = 0;
  for (auto const& tx : block.getTxs()) {
    this->processTransaction(tx,
      blockHash,
      block.getNHeight(),
      Secp256k1::toAddress(block.getValidatorPubKey()),
      block.getTimestamp(),
      100000000,
      this->options_.getChainID(),
      txIndex);
    txIndex++;
  }

  // Process rdPoS State
  this->rdpos_.processBlock(block);

  // Refresh the mempool based on the block transactions
  this->refreshMempool(block);
  Logger::logToDebug(LogType::INFO, Log::state, __func__, "Block " + block.hash().hex().get() + " processed successfully.");
  Utils::safePrint("Block: " + block.hash().hex().get() + " height: " + std::to_string(block.getNHeight()) + " was added to the blockchain");
  for (const auto& tx : block.getTxs()) {
    Utils::safePrint("Transaction: " + tx.hash().hex().get() + " was accepted in the blockchain");
  }

  // Move block to storage
  this->storage_.pushBack(std::move(block));
}

void State::fillBlockWithTransactions(Block& block) const {
  std::shared_lock lock(this->stateMutex_);
  for (const auto& [hash, tx] : this->mempool_) block.appendTx(tx);
}

TxInvalid State::validateTransaction(const TxBlock& tx) const {
  std::shared_lock lock(this->stateMutex_);
  return this->validateTransactionInternal(tx);
}

TxInvalid State::addTx(TxBlock&& tx) {
  auto TxInvalid = this->validateTransaction(tx);
  if (TxInvalid) return TxInvalid;
  std::unique_lock lock(this->stateMutex_);
  auto txHash = tx.hash();
  this->mempool_.insert({txHash, std::move(tx)});
  Utils::safePrint("Transaction: " + tx.hash().hex().get() + " was added to the mempool");
  return TxInvalid;
}

bool State::addValidatorTx(const TxValidator& tx) {
  std::unique_lock lock(this->stateMutex_);
  return this->rdpos_.addValidatorTx(tx);
}

bool State::isTxInMempool(const Hash& txHash) const {
  std::shared_lock lock(this->stateMutex_);
  return this->mempool_.contains(txHash);
}

std::unique_ptr<TxBlock> State::getTxFromMempool(const Hash &txHash) const {
  std::shared_lock lock(this->stateMutex_);
  auto it = this->mempool_.find(txHash);
  if (it == this->mempool_.end()) return nullptr;
  return std::make_unique<TxBlock>(it->second);
}

void State::addBalance(const Address& addr) {
  std::unique_lock lock(this->stateMutex_);
  this->evmHost_.accounts[addr].balance.first += uint256_t("1000000000000000000000");
  this->evmHost_.accounts[addr].balance.second += uint256_t("1000000000000000000000");
}

Bytes State::ethCall(const ethCallInfo& callInfo) const {
  const auto& [from, to, gasLimit, gasPrice, value, functor, data, fullData] = callInfo;

  std::shared_lock lock(this->stateMutex_);
  auto &address = std::get<1>(callInfo);
  if (this->contractManager_.isContractAddress(address)) {
    this->currentRandomGen_ = std::make_unique<RandomGen>(storage_.latest()->getBlockRandomness());
    this->contractManager_.updateRandomGen(this->currentRandomGen_.get());
    return this->contractManager_.callContract(callInfo);
  } else {
    if (this->evmHost_.isEvmContract(to) || to == Address()) {
      lock.unlock();
      std::unique_lock unique(this->stateMutex_);
      this->currentRandomGen_ = std::make_unique<RandomGen>(storage_.latest()->getBlockRandomness());
      Utils::safePrint("Estimating gas from evm...");
      if (value) {
        auto realTo = (to == Address()) ? this->evmHost_.deriveContractAddress(this->getNativeNonce(from), from) : to;
        this->evmHost_.accounts[from].balance.second -= value;
        this->evmHost_.accounts[realTo].balance.second += value;
        this->evmHost_.accessedAccountsBalances.push_back(from);
        this->evmHost_.accessedAccountsBalances.push_back(realTo);
      }
      uint256_t realGasLimit = gasLimit;
      auto latestBlock = this->storage_.latest();
      if (gasLimit > std::numeric_limits<int64_t>::max() - 10) {
        auto newCallInfo = callInfo;
        realGasLimit = std::numeric_limits<int64_t>::max() - 10;
        std::get<2>(newCallInfo) = std::numeric_limits<int64_t>::max() - 10;
        this->evmHost_.setTxContext(callInfo,
        latestBlock->hash(),
        latestBlock->getNHeight(),
        Secp256k1::toAddress(latestBlock->getValidatorPubKey()),
        latestBlock->getTimestamp(),
        100000000,
        this->options_.getChainID());
      } else {
        this->evmHost_.setTxContext(callInfo,
          latestBlock->hash(),
          latestBlock->getNHeight(),
          Secp256k1::toAddress(latestBlock->getValidatorPubKey()),
          latestBlock->getTimestamp(),
          100000000,
          this->options_.getChainID());
      }
      auto evmCallResult = this->evmHost_.execute(callInfo, this->currentRandomGen_.get());

      // Revert EVERYTHING from the call.
      this->evmHost_.revert();
      this->evmHost_.revertCode();
      this->evmHost_.revertBalance();

      if (evmCallResult.status_code) {
        throw DynamicException("Error when estimating gas, evmCallResult.status_code: " + std::string(evmc_status_code_to_string(evmCallResult.status_code)) + " bytes: " + Hex::fromBytes(Utils::cArrayToBytes(evmCallResult.output_data, evmCallResult.output_size)).get());
      }
      return Utils::cArrayToBytes(evmCallResult.output_data, evmCallResult.output_size);
    }
    return {};
  }
}

uint256_t State::estimateGas(const ethCallInfo& callInfo) {
  std::shared_lock lock(this->stateMutex_);
  uint64_t baseGas = 21000;
  const auto& [from, to, gasLimit, gasPrice, value, functor, data, fullData] = callInfo;

  // Check balance/gasLimit/gasPrice if available.
  if (from && value) {
    uint256_t totalGas = 0;
    if (gasLimit && gasPrice) {
      totalGas = gasLimit * gasPrice;
    }
    auto it = this->evmHost_.accounts.find(from);
    if (it == this->evmHost_.accounts.end()) return 0;
    if (it->second.balance.second < value + totalGas) return 0;
  }

  if (this->contractManager_.isContractAddress(to)) {
    Utils::safePrint("Estimating gas from state...");
    this->currentRandomGen_ = std::make_unique<RandomGen>(storage_.latest()->getBlockRandomness());
    this->contractManager_.updateRandomGen(this->currentRandomGen_.get());
    this->contractManager_.validateCallContractWithTx(callInfo);
  }

  if (this->evmHost_.isEvmContract(to) || to == Address()) {
    lock.unlock();
    this->currentRandomGen_ = std::make_unique<RandomGen>(storage_.latest()->getBlockRandomness());
    std::unique_lock unique(this->stateMutex_);
    Utils::safePrint("Estimating gas from evm..." + gasLimit.str());
    if (value) {
      Address realTo = (to == Address()) ? this->evmHost_.deriveContractAddress(this->getNativeNonce(from), from) : to;
      this->evmHost_.accounts[from].balance.second -= value;
      this->evmHost_.accounts[realTo].balance.second += value;
      this->evmHost_.accessedAccountsBalances.push_back(from);
      this->evmHost_.accessedAccountsBalances.push_back(realTo);
    }
    uint256_t realGasLimit = gasLimit;
    auto latestBlock = this->storage_.latest();
    if (gasLimit > std::numeric_limits<int64_t>::max() - 10) {
      auto newCallInfo = callInfo;
      realGasLimit = std::numeric_limits<int64_t>::max() - 10;
      std::get<2>(newCallInfo) = std::numeric_limits<int64_t>::max() - 10;
      this->evmHost_.setTxContext(callInfo,
      latestBlock->hash(),
      latestBlock->getNHeight(),
      Secp256k1::toAddress(latestBlock->getValidatorPubKey()),
      latestBlock->getTimestamp(),
      100000000,
      this->options_.getChainID());
    } else {
      this->evmHost_.setTxContext(callInfo,
        latestBlock->hash(),
        latestBlock->getNHeight(),
        Secp256k1::toAddress(latestBlock->getValidatorPubKey()),
        latestBlock->getTimestamp(),
        100000000,
        this->options_.getChainID());
    }
    auto evmCallResult = this->evmHost_.execute(callInfo, this->currentRandomGen_.get());
    // Revert EVERYTHING from the call.

    this->evmHost_.revert(true);
    this->evmHost_.revertCode();
    this->evmHost_.revertBalance();

    int64_t gasLeft = evmCallResult.gas_left;
    gasLeft - 21000;
    if (gasLeft < 0) {
      throw DynamicException("Error when estimating gas, gasLimit is lower than gas left");
    }

    if (evmCallResult.status_code) {
      throw DynamicException("Error when estimating gas, evmCallResult.status_code: " + std::string(evmc_status_code_to_string(evmCallResult.status_code)) + " bytes: " + Hex::fromBytes(Utils::cArrayToBytes(evmCallResult.output_data, evmCallResult.output_size)).get());
    }
    auto gasUsed = realGasLimit - evmCallResult.gas_left;
    return gasUsed + baseGas;
  }

  return baseGas;
}

void State::processContractPayable(const std::unordered_map<Address, uint256_t, SafeHash>& payableMap) {
  if (!this->processingPayable_) throw DynamicException(
    "Uh oh, contracts are going haywire! Cannot change State while not processing a payable contract."
  );
  for (const auto& [address, amount] : payableMap) {
    this->evmHost_.accessedAccountsBalances.push_back(this->contractManager_.getContractAddress());
    this->evmHost_.accounts[address].balance.second = amount;
  }
}

std::vector<std::pair<std::string, Address>> State::getContracts() const {
  std::shared_lock lock(this->stateMutex_);
  return this->contractManager_.getContracts();
}

std::vector<Address> State::getEvmContracts() const {
  std::shared_lock lock(this->stateMutex_);
  std::vector<Address> evmContracts;
  for (const auto& [txHash, addr] : this->evmHost_.contractAddresses) {
    evmContracts.push_back(addr);
  }
  return evmContracts;
}

bool State::isEvmContract(const Address& addr) const {
  std::shared_lock lock(this->stateMutex_);
  return this->evmHost_.isEvmContract(addr);
}

Bytes State::getContractCode(const Address& addr) const {
  std::shared_lock lock(this->stateMutex_);
  return this->evmHost_.accounts[addr].code.second;
}

Address State::getEvmContractAddress(const Hash& txHash) const {
  std::shared_lock lock(this->stateMutex_);
  return this->evmHost_.contractAddresses[txHash];
}

std::vector<Event> State::getEvents(
  const uint64_t& fromBlock, const uint64_t& toBlock,
  const Address& address, const std::vector<Hash>& topics
) const {
  std::shared_lock lock(this->stateMutex_);
  return this->contractManager_.getEvents(fromBlock, toBlock, address, topics);
}

std::vector<Event> State::getEvents(
  const Hash& txHash, const uint64_t& blockIndex, const uint64_t& txIndex
) const {
  std::shared_lock lock(this->stateMutex_);
  return this->contractManager_.getEvents(txHash, blockIndex, txIndex);
}

