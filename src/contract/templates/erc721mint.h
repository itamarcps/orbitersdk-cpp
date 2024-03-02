#ifndef ERC721_MINT
#define ERC721_MINT


// ERC721Mint derives from base ERC721
#include "erc721.h"
#include "../variables/safeaddress.h"


/*
 * ERC721Mint
 * Based on erc721mint.sol on rollup-contract
 */

class ERC721Mint : public ERC721 {
  private:
    // BurnedToken struct
    // Struct to store the burned token
    // first - if the token exists
    // second - the user who burned the token
    // third - the v value of the signature
    // fourth - the r value of the signature
    // fifth - the s value of the signature
    // sixth - the rarity of the token
    using BurnedToken = std::tuple<bool, Address, uint8_t, Hash, Hash, uint256_t>;

    SafeString _tokenBaseURI; ///< Base URI for the token
    SafeUint256_t tokenIdCounter_; ///< TokenId Counter for the public mint() functions.
    SafeUint256_t totalSupply_; ///< How many tokens exist.
    SafeUint256_t maxSupply_; ///< How many tokens can be minted (used by mint()).
    SafeAddress signer_; ///< The signer address for the burn function
    SafeUnorderedMap<uint256_t, BurnedToken> preBurnedTokens_; ///< Pre-burned tokens
    SafeUnorderedMap<uint256_t, BurnedToken> burnedTokens_; ///< Burned tokens
    SafeUnorderedMap<uint256_t, uint256_t> tokenIdRarity_;
    SafeUnorderedMap<uint256_t, std::string> tokenURI_;
  /// mapping(address owner => mapping(uint256 index => uint256)) private _ownedTokens;
    SafeUnorderedMap<Address, std::unordered_map<uint256_t, uint256_t>> _ownedTokens;
  /// mapping(address owner => mapping(uint256 tokenId => uint256)) private _ownedTokensIndex;
    SafeUnorderedMap<Address, std::unordered_map<uint256_t, uint256_t>> _ownedTokensIndex;
    void registerContractFunctions() override; ///< Register contract functions.

    void setTokenURI(const uint256_t& tokenId, const std::string& tokenURI);
  public:

    void PreBurnedEvent(const EventParam<uint256_t, false>& tokenId, const EventParam<Address, false>& addr, const EventParam<uint256_t, false>& rarity) {
      this->emitEvent(__func__, std::make_tuple(tokenId, addr, rarity));
    }

    void MetadataUpdate(const EventParam<uint256_t, false>& tokenId) {
      this->emitEvent(__func__, std::make_tuple(tokenId));
    }
    /**
     * ConstructorArguments is a tuple of the contract constructor arguments in
     * the order they appear in the constructor.
     */
    using ConstructorArguments =
       std::tuple<const std::string &, const std::string &, const uint256_t&, const Address &, const std::string& >;

    /**
     * Constructor for loading contract from DB.
     * @param interface Reference to the contract manager interface.
     * @param address The address where the contract will be deployed.
     * @param db Reference to the database object.
     */
    ERC721Mint(ContractManagerInterface &interface, const Address &address, DB& db);

    /**
     * Constructor to be used when creating a new contract.
     * @param erc721name The name of the ERC721 token.
     * @param erc721symbol The symbol of the ERC721 token.
     * @param maxTokens The maximum amount of tokens that can be minted
     * @param signer The signer address for the burn function
     * @param interface Reference to the contract manager interface.
     * @param address The address where the contract will be deployed.
     * @param creator The address of the creator of the contract.
     * @param chainId The chain where the contract wil be deployed.
     * @param db Reference to the database object.
     */
    ERC721Mint(const std::string &erc721name, const std::string &erc721symbol, const uint256_t& maxSupply, const Address &signer, const std::string& tokenBaseURI,
           ContractManagerInterface &interface, const Address &address,
           const Address &creator, const uint64_t &chainId,
           DB& db);

    /// Destructor.
    ~ERC721Mint() override;

    void mint(const Address& to);

    void preBurn (const uint256_t& tokenId);

    void burn (const uint256_t& tokenId, const uint8_t& v, const Hash& r, const Hash& s);

    void setBaseURI(const std::string& baseURI);

    std::string getTokenRarity(const uint256_t& tokenRarity) const {
      if (tokenRarity == 0) {
        return "bronze";
      } else if (tokenRarity == 1) {
        return "silver";
      } else if (tokenRarity == 2) {
        return "gold";
      } else {
        throw DynamicException("ERC72Mint::getTokenRarity: invalid token rarity");
      }
    }

    std::string _baseURI() const {
      return _tokenBaseURI.get();
    }

    std::string tokenURI(const uint256_t& tokenId) const override {
      Address owner = this->ownerOf_(tokenId);
      if (owner == Address()) {
        throw DynamicException("ERC72Mint::tokenURI: inexistent token");
      }

      auto _tokenURIit = this->tokenURI_.find(tokenId);
      std::string _tokenURI = "";
      if (_tokenURIit != this->tokenURI_.end()) {
        _tokenURI = _tokenURIit->second;
      }
      const auto& base = this->_baseURI();
      if (base.size() == 0) {
        return _tokenURI;
      }

      if (_tokenURI.size() > 0) {
        return base + _tokenURI;
      }

      return ERC721::tokenURI(tokenId);
    }

  /*
  *        uint256 tokenCount = balanceOf(user);
  uint256[] memory ownedTokens = new uint256[](tokenCount);

  for (uint256 i = 0; i < tokenCount; i++) {
  ownedTokens[i] = _ownedTokens[user][i];
  }

  return ownedTokens;
  */
    std::vector<uint256_t> getAllTokensOwnedByUser(const Address& user) const {
      std::vector<uint256_t> tokens;
      auto it = this->_ownedTokens.find(user);
      if (it != this->_ownedTokens.end()) {
        auto& userTokens = it->second;
        for (auto& token : userTokens) {
          tokens.push_back(token.first);
        }
      }
      return tokens;
    }

    Bytes message (const uint256_t& tokenId, const Address& user) const;

    Hash _toTyped32ByteDataHash (const Hash& messageHash) const;

    uint256_t tokenIdCounter() const {
      return tokenIdCounter_.get();
    }

    uint256_t totalSupply() const {
      return totalSupply_.get();
    }

    uint256_t maxSupply() const {
      return maxSupply_.get();
    }

    Address signer() const {
      return signer_.get();
    }

    BurnedToken preBurnedTokens(const uint256_t& tokenId) const {
      auto it = this->preBurnedTokens_.find(tokenId);
      if (it != this->preBurnedTokens_.end()) {
        return it->second;
      }
      return BurnedToken(false, Address(), 0, 0, 0, 0);
    }

    BurnedToken burnedTokens(const uint256_t& tokenId) const {
      auto it = this->burnedTokens_.find(tokenId);
      if (it != this->burnedTokens_.end()) {
        return it->second;
      }
      return BurnedToken(false, Address(), 0, 0, 0, 0);
    }

    /// Register contract class via ContractReflectionInterface.
    static void registerContract() {
      ContractReflectionInterface::registerContractMethods<
        ERC721Mint, const std::string &, const std::string &, const uint256_t &, const Address &,
        ContractManagerInterface &, const Address &, const Address &,
        const uint64_t &, DB&>
      (
        std::vector<std::string>{"erc721name", "erc721symbol", "maxSupply", "signer", "baseURI"},
        std::make_tuple("mint", &ERC721Mint::mint, FunctionTypes::NonPayable, std::vector<std::string>{"to"}),
        std::make_tuple("preBurn", &ERC721Mint::preBurn, FunctionTypes::NonPayable, std::vector<std::string>{"tokenId"}),
        std::make_tuple("burn", &ERC721Mint::burn, FunctionTypes::NonPayable, std::vector<std::string>{"tokenId", "v", "r", "s"}),
        std::make_tuple("message", &ERC721Mint::message, FunctionTypes::View, std::vector<std::string>{"tokenId", "user"}),
        std::make_tuple("_toTyped32ByteDataHash", &ERC721Mint::_toTyped32ByteDataHash, FunctionTypes::View, std::vector<std::string>{"messageHash"}),
        std::make_tuple("tokenIdCounter", &ERC721Mint::tokenIdCounter, FunctionTypes::View, std::vector<std::string>{""}),
        std::make_tuple("maxSupply", &ERC721Mint::maxSupply, FunctionTypes::View, std::vector<std::string>{""}),
        std::make_tuple("totalSupply", &ERC721Mint::totalSupply, FunctionTypes::View, std::vector<std::string>{""}),
        std::make_tuple("signer", &ERC721Mint::signer, FunctionTypes::View, std::vector<std::string>{""}),
        std::make_tuple("preBurnedTokens", &ERC721Mint::preBurnedTokens, FunctionTypes::View, std::vector<std::string>{"tokenId"}),
        std::make_tuple("burnedTokens", &ERC721Mint::burnedTokens, FunctionTypes::View, std::vector<std::string>{"tokenId"}),
        std::make_tuple("setBaseURI", &ERC721Mint::setBaseURI, FunctionTypes::NonPayable, std::vector<std::string>{"baseURI"}),
        std::make_tuple("getTokenRarity", &ERC721Mint::getTokenRarity, FunctionTypes::View, std::vector<std::string>{"tokenRarity"}),
        std::make_tuple("_baseURI", &ERC721Mint::_baseURI, FunctionTypes::View, std::vector<std::string>{""}),
        std::make_tuple("tokenURI", &ERC721Mint::tokenURI, FunctionTypes::View, std::vector<std::string>{"tokenId"}),
        std::make_tuple("getAllTokensOwnedByUser", &ERC721Mint::getAllTokensOwnedByUser, FunctionTypes::View, std::vector<std::string>{"user"})
      );
      ContractReflectionInterface::registerContractEvents<ERC721Mint>(
        std::make_tuple("PreBurnedEvent", false, &ERC721Mint::PreBurnedEvent, std::vector<std::string>{"from", "to", "value", "rarity"}),
        std::make_tuple("MetadataUpdate", false, &ERC721Mint::MetadataUpdate, std::vector<std::string>{"tokenId"})
      );
    }
};

#endif // ERC721_MINT
