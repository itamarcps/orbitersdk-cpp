#include "contractmanager.h"
#include "erc20.h"
#include "../core/rdpos.h"

ContractManager::ContractManager(const std::unique_ptr<DB>& db, const std::unique_ptr<rdPoS>& rdpos, const std::unique_ptr<Options>& options) :
  BaseContract("ContractManager", ProtocolContractAddresses.at("ContractManager"), Address(Hex::toBytes("0x00dead00665771855a34155f5e7405489df2c3c6"), true), 0, db), rdpos(rdpos), options(options) {
  /// Load Contracts from DB.
  auto contracts = this->db->getBatch(DBPrefix::contractManager);
  for (const auto& contract : contracts) {
   if (contract.value == "ERC20") {
     Address contractAddress(contract.key, true);
     this->contracts.insert(std::make_pair(contractAddress, std::make_unique<ERC20>(contractAddress, this->db)));
     continue;
   }
    throw std::runtime_error("Unknown contract: " + contract.value);
  }
}

ContractManager::~ContractManager() {
  DBBatch contractsBatch;
  for (const auto& [contractAddress, contract] : this->contracts) {
    contractsBatch.puts.push_back(DBEntry(contractAddress.get(), contract->getContractName()));
  }
  this->db->putBatch(contractsBatch, DBPrefix::contractManager);
}

Address ContractManager::deriveContractAddress(const ethCallInfo& callInfo) const {
  /// Contract address = sha3(rlp(tx.from() + tx.nonce()).substr(12);
  uint8_t rlpSize = 0xc0;
  rlpSize += this->getCaller().size();
  /// As we don't have actually access to the nonce, we will use the number of contracts existing in the chain
  rlpSize += (this->contracts.size() < 0x80) ? 1 : 1 + Utils::bytesRequired(this->contracts.size());
  std::string rlp;
  rlp += rlpSize;
  rlp += this->getCaller().get();
  rlp += (this->contracts.size() < 0x80) ? (char)this->contracts.size() : (char)0x80 + Utils::bytesRequired(this->contracts.size());
  return Address(Utils::sha3(rlp).get().substr(12), true);
}

void ContractManager::createNewERC20Contract(const ethCallInfo& callInfo) {
  if (this->caller != this->getContractCreator()) {
    throw std::runtime_error("Only contract creator can create new contracts");
  }
  /// Check if desired contract address already exists
  const auto derivedContractAddress = this->deriveContractAddress(callInfo);
  if (this->contracts.contains(derivedContractAddress)) {
    throw std::runtime_error("Contract already exists");
  }

  std::unique_lock lock(this->contractsMutex);
  for (const auto& [protocolContractName, protocolContractAddress] : ProtocolContractAddresses) {
    if (protocolContractAddress == derivedContractAddress) {
      throw std::runtime_error("Contract already exists");
    }
  }

  /// Parse the constructor ABI
  std::vector<ABI::Types> types = { ABI::Types::string, ABI::Types::string, ABI::Types::uint256, ABI::Types::uint256};
  ABI::Decoder decoder(types, std::get<5>(callInfo).substr(4));

  /// Check if decimals are within range
  if (decoder.getData<uint256_t>(2) > 255) {
    throw std::runtime_error("Decimals must be between 0 and 255");
  }

  /// Create the contract
  this->contracts.insert(std::make_pair(derivedContractAddress, std::make_unique<ERC20>(decoder.getData<std::string>(0),
                                                                                        decoder.getData<std::string>(1),
                                                                                        uint8_t(decoder.getData<uint256_t>(2)),
                                                                                        decoder.getData<uint256_t>(3),
                                                                                        derivedContractAddress,
                                                                                        this->getCaller(),
                                                                                        this->options->getChainID(),
                                                                                        this->db)));
  return;
}

void ContractManager::validateCreateNewERC20Contract(const ethCallInfo &callInfo) const {
  if (this->caller != this->getContractCreator()) {
    throw std::runtime_error("Only contract creator can create new contracts");
  }
  /// Check if desired contract address already exists
  const auto derivedContractAddress = this->deriveContractAddress(callInfo);
  {
    std::shared_lock lock(this->contractsMutex);
    if (this->contracts.contains(derivedContractAddress)) {
      throw std::runtime_error("Contract already exists");
    }
  }

  for (const auto& [protocolContractName, protocolContractAddress] : ProtocolContractAddresses) {
    if (protocolContractAddress == derivedContractAddress) {
      throw std::runtime_error("Contract already exists");
    }
  }

  /// Parse the constructor ABI
  std::vector<ABI::Types> types = { ABI::Types::string, ABI::Types::string, ABI::Types::uint256, ABI::Types::uint256};
  ABI::Decoder decoder(types, std::get<5>(callInfo).substr(4));

  /// Check if decimals are within range
  if (decoder.getData<uint256_t>(2) > 255) {
    throw std::runtime_error("Decimals must be between 0 and 255");
  }

  return;
}

void ContractManager::ethCall(const ethCallInfo& callInfo) {
  std::string functor = std::get<5>(callInfo).substr(0, 4);

  /// function createNewERC20Contract(string memory name, string memory symbol, uint8 decimals, uint256 supply) public {}
  if (this->getCommit()) {
    if (functor == Hex::toBytes("0xb74e5ed5")) {
      this->createNewERC20Contract(callInfo);
      return;
    }
  } else {
    if (functor == Hex::toBytes("0xb74e5ed5")) {
      this->validateCreateNewERC20Contract(callInfo);
      return;
    }
  }
  throw std::runtime_error("Invalid function call");
}

std::string ContractManager::getDeployedContracts() const {
  std::unique_lock lock(this->contractsMutex);
  std::vector<std::string> names;
  std::vector<Address> addresses;
  for (const auto& [address, contract] : this->contracts) {
    names.push_back(contract->getContractName());
    addresses.push_back(address);
  }
  ABI::Encoder::EncVar vars;
  vars.push_back(names);
  vars.push_back(addresses);
  return ABI::Encoder(vars).getRaw();
}

const std::string ContractManager::ethCallView(const ethCallInfo& data) const {
  std::string functor = std::get<5>(data).substr(0, 4);

  /// function getDeployedContracts() public view returns (string[] memory, address[] memory) {}
  if (functor == Hex::toBytes("0xaa9a068f")) {
    return this->getDeployedContracts();
  }

  throw std::runtime_error("Invalid function call");
}

void ContractManager::callContract(const TxBlock& tx) {
  if (tx.getTo() == this->getContractAddress()) {
    this->caller = tx.getFrom();
    this->origin = tx.getFrom();
    this->value = tx.getValue();
    this->commit = true;
    try {
      this->ethCall(tx.txToCallInfo());
    } catch (std::exception &e) {
      this->commit = false;
      throw e;
    }
    this->commit = false;
    return;
  }

  if (tx.getTo() == ProtocolContractAddresses.at("rdPoS")) {
    rdpos->caller = tx.getFrom();
    rdpos->origin = tx.getFrom();
    rdpos->value = tx.getValue();
    rdpos->commit = true;
    try {
      rdpos->ethCall(tx.txToCallInfo());
    } catch (std::exception &e) {
      rdpos->commit = false;
      throw e;
    }
    rdpos->commit = false;
    return;
  }

  std::unique_lock lock(this->contractsMutex);
  if (!this->contracts.contains(tx.getTo())) {
    throw std::runtime_error("Contract does not exist");
  }

  const auto& contract = contracts.at(tx.getTo());
  contract->caller = tx.getFrom();
  contract->origin = tx.getFrom();
  contract->value = tx.getValue();
  contract->commit = true;
  try {
    contract->ethCall(tx.txToCallInfo());
  } catch (std::exception &e) {
    contract->commit = false;
    throw e;
  }
  contract->commit = false;
}

bool ContractManager::validateCallContractWithTx(const ethCallInfo& callInfo) {
  const auto& [from, to, gasLimit, gasPrice, value, data] = callInfo;

  if (to == this->getContractAddress()) {
    this->caller = from;
    this->origin = from;
    this->value = value;
    this->commit = false;
    this->ethCall(callInfo);
    return true;
  }

  if (to == ProtocolContractAddresses.at("rdPoS")) {
    rdpos->caller = from;
    rdpos->origin = from;
    rdpos->value = value;
    rdpos->commit = false;
    rdpos->ethCall(callInfo);
    return true;
  }

  std::shared_lock lock(this->contractsMutex);
  if (!this->contracts.contains(to)) {
    return false;
  }
  const auto& contract = contracts.at(to);
  contract->caller = from;
  contract->origin = from;
  contract->value = value;
  contract->commit = false;
  contract->ethCall(callInfo);
  return true;
}

const std::string ContractManager::callContract(const ethCallInfo& callInfo) const {
  const auto& [from, to, gasLimit, gasPrice, value, data] = callInfo;
  if (to == this->getContractAddress()) {
    return this->ethCallView(callInfo);
  }

  if (to == ProtocolContractAddresses.at("rdPoS")) {
    return rdpos->ethCallView(callInfo);
  }

  std::shared_lock lock(this->contractsMutex);
  if (!this->contracts.contains(to)) {
    throw std::runtime_error("Contract does not exist");
  }
  return this->contracts.at(to)->ethCallView(callInfo);
}

bool ContractManager::isContractCall(const TxBlock &tx) const {
  if (tx.getTo() == this->getContractAddress()) {
    return true;
  }
  for (const auto& [protocolContractName, protocolContractAddress] : ProtocolContractAddresses) {
    if (tx.getTo() == protocolContractAddress) {
      return true;
    }
  }

  std::shared_lock lock(this->contractsMutex);
  return this->contracts.contains(tx.getTo());
}

bool ContractManager::isContractAddress(const Address &address) const {
  std::shared_lock(this->contractsMutex);
  return this->contracts.contains(address);
}

std::vector<std::pair<std::string, Address>> ContractManager::getContracts() const {
  std::shared_lock lock(this->contractsMutex);
  std::vector<std::pair<std::string, Address>> contracts;
  for (const auto& [address, contract] : this->contracts) {
    contracts.push_back({contract->getContractName(), address});
  }
  return contracts;
}
