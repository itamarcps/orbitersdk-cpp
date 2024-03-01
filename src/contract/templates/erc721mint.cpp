#include "erc721mint.h"

/**
* Based on
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "hardhat/console.sol";

contract MyTokenMintable is ERC721 {

    struct BurnedToken {
        bool exists;
        address user;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    uint256 private tokenIdCounter_;
    uint256 private totalSupply_;
    uint256 private immutable maxSupply_;
    address private immutable signer_;
    mapping (uint256 => BurnedToken) private preBurnedTokens_;
    mapping (uint256 => BurnedToken) private burnedTokens_;

    // Event
    // Event to log preBurn
    event PreBurnedEvent(
        uint256 tokenId,
        address claimableOwner
    );

    /// Initialize the contract with the max supply and the signer address
    constructor(uint256 maxSupplyInit, address signerInit) // Name and ticker of the token
        ERC721("MyTokenMintable", "MTM") {
        // Contract parameters initialization
        tokenIdCounter_ = 0;
        totalSupply_ = 0;
        maxSupply_ = maxSupplyInit;
        signer_ = signerInit;
    }

    function mint(address to) external {
        require(tokenIdCounter_ < maxSupply_, "MyTokenMintable: max supply reached");
        // Mint the NFT to the user's provided address
        _safeMint(to, tokenIdCounter_);
        // Housekeeping parameters
        tokenIdCounter_++;
        totalSupply_++;
    }

    function preBurn(uint256 tokenId) external {
        require(_msgSender() == ownerOf(tokenId), "MyTokenMintable: caller is not the owner");
        // burn the token
        _burn(tokenId);
        // Annotate the tokenId and the user (who is the owner of the token) as pre-burned
        preBurnedTokens_[tokenId] = BurnedToken(true, _msgSender(), 0, 0x0, 0x0);
        // Emit Preburned event
        emit PreBurnedEvent(tokenId, _msgSender());
    }

  function burn(uint256 tokenId, uint8 v, bytes32 r, bytes32 s) external {
        require(preBurnedTokens_[tokenId].exists, "MyTokenMintable: token is not pre-burned");

        // Create the message hash based on the tokenId and the user, use abi non-standard packed encoding
        bytes32 messageHash = keccak256(message(tokenId, preBurnedTokens_[tokenId].user));
        // Hash the message to standardize EIP 712 without Domain for using eth_sign in ethers
        address recoveredSigner = ecrecover(_toTyped32ByteDataHash(messageHash), v, r, s);

        // Check if the signer is the same as the signer of the contract
        require(recoveredSigner == signer_, "MyToken Mintable: invalid signature");
        // Annotate the tokenId and the user (who is the owner of the token) as burned
        burnedTokens_[tokenId] = BurnedToken(true, preBurnedTokens_[tokenId].user, v, r, s);
        // Remove the tokenId from the pre-burned tokens
        delete preBurnedTokens_[tokenId];
    }

    function message (uint256 tokenId, address user) public pure returns (bytes memory) {
        return abi.encodePacked(tokenId, user);
    }

    function _toTyped32ByteDataHash(bytes32 messageHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }



    /// Getter for the total supply
    function totalSupply() external view returns (uint256) {
        return totalSupply_;
    }

    /// Getter for the max supply
    function maxSupply() external view returns (uint256) {
        return maxSupply_;
    }

    /// Getter for the signer
    function signer() external view returns (address) {
        return signer_;
    }

    /// Getter for the pre-burned tokens
    function preBurnedTokens(uint256 tokenId) external view returns (BurnedToken memory) {
        return preBurnedTokens_[tokenId];
    }

    /// Getter for the burned tokens
    function burnedTokens(uint256 tokenId) external view returns (BurnedToken memory) {
        return burnedTokens_[tokenId];
    }

    /// Getter for the tokenIdCounter
    function tokenIdCounter() external view returns (uint256) {
        return tokenIdCounter_;
    }
}
 *
*/

ERC721Mint::ERC721Mint(ContractManagerInterface &interface, const Address &address, DB& db)
: ERC721(interface, address, db), tokenIdCounter_(this), totalSupply_(this), maxSupply_(this), signer_(this), preBurnedTokens_(this), burnedTokens_(this)
{
  this->tokenIdCounter_ = Utils::bytesToUint256(this->db_.get(std::string("tokenIdCounter_"), this->getDBPrefix()));
  this->totalSupply_ = Utils::bytesToUint256(this->db_.get(std::string("totalSupply_"), this->getDBPrefix()));
  this->maxSupply_ = Utils::bytesToUint256(this->db_.get(std::string("maxSupply_"), this->getDBPrefix()));
  this->signer_ = Address(this->db_.get(std::string("signer_"), this->getDBPrefix()));

  auto preBurnedTokens = this->db_.getBatch(this->getNewPrefix("preBurnedTokens_"));
  for (const auto& dbEntry : preBurnedTokens) {
    BytesArrView value(dbEntry.value);
    Address user(value.subspan(0,20));
    uint8_t v = value[20];
    uint256_t r = Utils::fromBigEndian<uint256_t>(value.subspan(21,32));
    uint256_t s = Utils::fromBigEndian<uint256_t>(value.subspan(53,32));
    this->preBurnedTokens_[Utils::fromBigEndian<uint256_t>(dbEntry.key)] = std::make_tuple(true, user, v, r, s);
  }

  auto burnedTokens = this->db_.getBatch(this->getNewPrefix("burnedTokens_"));
  for (const auto& dbEntry : burnedTokens) {
    BytesArrView value(dbEntry.value);
    Address user(value.subspan(0,20));
    uint8_t v = value[20];
    uint256_t r = Utils::fromBigEndian<uint256_t>(value.subspan(21,32));
    uint256_t s = Utils::fromBigEndian<uint256_t>(value.subspan(53,32));
    this->burnedTokens_[Utils::fromBigEndian<uint256_t>(dbEntry.key)] = std::make_tuple(true, user, v, r, s);
  }

  this->tokenIdCounter_.commit();
  this->totalSupply_.commit();
  this->maxSupply_.commit();
  this->signer_.commit();
  this->preBurnedTokens_.commit();
  this->burnedTokens_.commit();

  this->registerContractFunctions();

  this->tokenIdCounter_.enableRegister();
  this->totalSupply_.enableRegister();
  this->maxSupply_.enableRegister();
  this->signer_.enableRegister();
  this->preBurnedTokens_.enableRegister();
  this->burnedTokens_.enableRegister();

}

ERC721Mint::ERC721Mint(
  const std::string &erc721name, const std::string &erc721symbol, const uint256_t& maxTokens, const Address &signer,
  ContractManagerInterface &interface, const Address &address,
  const Address &creator, const uint64_t &chainId, DB& db)
: ERC721("ERC721Mint", erc721name, erc721symbol, interface, address, creator, chainId, db),
  tokenIdCounter_(this, 0), maxSupply_(this, maxTokens), totalSupply_(this, 0), signer_(this, signer), preBurnedTokens_(this), burnedTokens_(this)
{
  tokenIdCounter_.commit();
  maxSupply_.commit();
  totalSupply_.commit();
  signer_.commit();
  preBurnedTokens_.commit();
  burnedTokens_.commit();

  this->registerContractFunctions();

  tokenIdCounter_.enableRegister();
  maxSupply_.enableRegister();
  totalSupply_.enableRegister();
  signer_.enableRegister();
  preBurnedTokens_.enableRegister();
  burnedTokens_.enableRegister();
}

ERC721Mint::~ERC721Mint() {
  this->db_.put(std::string("tokenIdCounter_"), Utils::uint256ToBytes(this->tokenIdCounter_.get()), this->getDBPrefix());
  this->db_.put(std::string("totalSupply_"), Utils::uint256ToBytes(this->totalSupply_.get()), this->getDBPrefix());
  this->db_.put(std::string("maxSupply_"), Utils::uint256ToBytes(this->maxSupply_.get()), this->getDBPrefix());
  this->db_.put(std::string("signer_"), this->signer_.get().asBytes(), this->getDBPrefix());
  DBBatch batch;
  for (auto it = this->preBurnedTokens_.cbegin(); it != this->preBurnedTokens_.cend(); ++it) {
    const auto& [ exists, user, v, r, s ] = it->second;
    // Key: tokenId
    // Value: user (20 bytes) + v (1 byte) + r (32 bytes) + s (32 bytes)
    Bytes value = user.asBytes();
    value.insert(value.end(), uint8_t(v));
    Utils::appendBytes(value, r.asBytes());
    Utils::appendBytes(value, s.asBytes());
    batch.push_back(Utils::uint256ToBytes(it->first), value, this->getNewPrefix("preBurnedTokens_"));
  }
  for (auto it = this->burnedTokens_.cbegin(); it != this->burnedTokens_.cend(); ++it) {
    const auto& [ exists, user, v, r, s ] = it->second;
    // Key: tokenId
    // Value: user (20 bytes) + v (1 byte) + r (32 bytes) + s (32 bytes)
    Bytes value = user.asBytes();
    value.insert(value.end(), uint8_t(v));
    Utils::appendBytes(value, r.asBytes());
    Utils::appendBytes(value, s.asBytes());
    batch.push_back(Utils::uint256ToBytes(it->first), value, this->getNewPrefix("burnedTokens_"));
  }
  this->db_.putBatch(batch);
}

void ERC721Mint::registerContractFunctions() {
  this->registerContract();
  this->registerMemberFunction("mint", &ERC721Mint::mint,  FunctionTypes::NonPayable, this);
  this->registerMemberFunction("burn", &ERC721Mint::burn, FunctionTypes::NonPayable, this);
  this->registerMemberFunction("preBurn", &ERC721Mint::preBurn, FunctionTypes::NonPayable, this);
  this->registerMemberFunction("message", &ERC721Mint::message, FunctionTypes::View, this);
  this->registerMemberFunction("_toTyped32ByteDataHash", &ERC721Mint::_toTyped32ByteDataHash, FunctionTypes::View, this);
  this->registerMemberFunction("tokenIdCounter", &ERC721Mint::tokenIdCounter, FunctionTypes::View, this);
  this->registerMemberFunction("maxSupply", &ERC721Mint::maxSupply, FunctionTypes::View, this);
  this->registerMemberFunction("totalSupply", &ERC721Mint::totalSupply, FunctionTypes::View, this);
  this->registerMemberFunction("signer", &ERC721Mint::signer, FunctionTypes::View, this);
  this->registerMemberFunction("preBurnedTokens", &ERC721Mint::preBurnedTokens, FunctionTypes::View, this);
  this->registerMemberFunction("burnedTokens", &ERC721Mint::burnedTokens, FunctionTypes::View, this);
}

void ERC721Mint::mint(const Address& to) {
  if(this->tokenIdCounter_.get() >= this->maxSupply_.get()) {
    throw DynamicException("MyTokenMintable: max supply reached");
  }
  // Mint the NFT to the user's provided address
  this->mint_(to, this->tokenIdCounter_.get());
  // Housekeeping parameters
  this->tokenIdCounter_ += 1;
  this->totalSupply_ += 1;
}

void ERC721Mint::preBurn (const uint256_t& tokenId) {
  if(this->ownerOf(tokenId) != this->getCaller()) {
    throw DynamicException("MyTokenMintable: caller is not the owner");
  }
  // burn the token
  this->burn_(tokenId);
  // Annotate the tokenId and the user (who is the owner of the token) as pre-burned
  this->preBurnedTokens_[tokenId] = std::make_tuple(true, this->getCaller(), 0, Hash(), Hash());
  // Emit Preburned event
  this->PreBurnedEvent(tokenId, this->getCaller());
}

void ERC721Mint::burn (const uint256_t& tokenId, const uint8_t& v, const Hash& r, const Hash& s) {
  const auto& [ exists, user, v_, r_, s_ ] = this->preBurnedTokens_[tokenId];

  if(!exists) {
    throw DynamicException("MyTokenMintable: token is not pre-burned");
  }

  // Create the message hash based on the tokenId and the user, use abi non-standard packed encoding
  auto hash = Utils::sha3(this->message(tokenId, user));
  auto messageHash = this->_toTyped32ByteDataHash(hash);
  // Hash the message to standardize EIP 712 without Domain for using eth_sign in ethers
  uint8_t realV = v;
  if (realV != 27 && realV != 28) {
    throw DynamicException("MyToken Mintable: invalid signature: realV: " + std::to_string(realV));
  }
  realV = realV - 27;
  auto signature = Secp256k1::makeSig(r.toUint256(), s.toUint256(), realV);
  auto recoveredSigner = Secp256k1::toAddress(Secp256k1::recover(signature, messageHash));

  // Check if the signer is the same as the signer of the contract
  if(recoveredSigner != this->signer_.get()) {
    throw DynamicException("MyToken Mintable: invalid signature: got: " + recoveredSigner.hex().get() + " expected: " + this->signer_.get().hex().get());
  }
  // Annotate the tokenId and the user (who is the owner of the token) as burned
  this->burnedTokens_[tokenId] = std::make_tuple(true, user, v, r, s);
  // Remove the tokenId from the pre-burned tokens
  this->preBurnedTokens_.erase(tokenId);
}


Bytes ERC721Mint::message (const uint256_t& tokenId, const Address& user) const {
  Bytes value;
  value.reserve(52); // 32 bytes for tokenId and 20 bytes for user
  Utils::appendBytes(value, Utils::uint256ToBytes(tokenId));
  Utils::appendBytes(value, user.asBytes());
  return value;
}

Hash ERC721Mint::_toTyped32ByteDataHash (const Hash& messageHash) const {
  Bytes value;
  value.insert(value.end(), 0x19);
  std::string ethereumSignedMessage = "Ethereum Signed Message:";
  Utils::appendBytes(value, ethereumSignedMessage);
  value.insert(value.end(), '\n');
  Utils::appendBytes(value, std::to_string(32));
  Utils::appendBytes(value, messageHash);
  return Utils::sha3(value);
}

