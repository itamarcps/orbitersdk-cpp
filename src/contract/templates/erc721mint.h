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
    using BurnedToken = std::tuple<bool, Address, uint8_t, Hash, Hash>;

    SafeUint256_t tokenIdCounter_; ///< TokenId Counter for the public mint() functions.
    SafeUint256_t totalSupply_; ///< How many tokens exist.
    SafeUint256_t maxSupply_; ///< How many tokens can be minted (used by mint()).
    SafeAddress signer_; ///< The signer address for the burn function
    SafeUnorderedMap<uint256_t, BurnedToken> preBurnedTokens_; ///< Pre-burned tokens
    SafeUnorderedMap<uint256_t, BurnedToken> burnedTokens_; ///< Burned tokens
    void registerContractFunctions() override; ///< Register contract functions.

  public:

    void PreBurnedEvent(const EventParam<uint256_t, false>& tokenId, const EventParam<Address, false>& addr) {
      this->emitEvent(__func__, std::make_tuple(tokenId, addr));
    }
    /**
     * ConstructorArguments is a tuple of the contract constructor arguments in
     * the order they appear in the constructor.
     */
    using ConstructorArguments =
       std::tuple<const std::string &, const std::string &, const uint256_t&, const Address &>;

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
    ERC721Mint(const std::string &erc721name, const std::string &erc721symbol, const uint256_t& maxSupply, const Address &signer,
           ContractManagerInterface &interface, const Address &address,
           const Address &creator, const uint64_t &chainId,
           DB& db);

    /// Destructor.
    ~ERC721Mint() override;

    void mint(const Address& to);

    void preBurn (const uint256_t& tokenId);

    void burn (const uint256_t& tokenId, const uint8_t& v, const Hash& r, const Hash& s);

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
      return BurnedToken(false, Address(), 0, 0, 0);
    }

    BurnedToken burnedTokens(const uint256_t& tokenId) const {
      auto it = this->burnedTokens_.find(tokenId);
      if (it != this->burnedTokens_.end()) {
        return it->second;
      }
      return BurnedToken(false, Address(), 0, 0, 0);
    }

    /// Register contract class via ContractReflectionInterface.
    static void registerContract() {
      ContractReflectionInterface::registerContractMethods<
        ERC721Mint, const std::string &, const std::string &, const uint256_t &, const Address &,
        ContractManagerInterface &, const Address &, const Address &,
        const uint64_t &, DB&>
      (
        std::vector<std::string>{"erc721name", "erc721symbol", "maxSupply", "signer"},
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
        std::make_tuple("burnedTokens", &ERC721Mint::burnedTokens, FunctionTypes::View, std::vector<std::string>{"tokenId"})
      );
      ContractReflectionInterface::registerContractEvents<ERC721Mint>(
        std::make_tuple("PreBurnedEvent", false, &ERC721Mint::PreBurnedEvent, std::vector<std::string>{"from", "to", "value"})
      );
    }
};

#endif // ERC721_MINT
