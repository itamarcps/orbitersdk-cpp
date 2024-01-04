/*
Copyright (c) [2023] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include "../../src/libs/catch2/catch_amalgamated.hpp"
#include "../../src/contract/templates/erc20.h"
#include "../../src/contract/abi.h"
#include "../../src/utils/db.h"
#include "../../src/utils/options.h"
#include "../../src/contract/contractmanager.h"
#include "../../src/core/rdpos.h"

#include <filesystem>

ethCallInfoAllocated buildCallInfo(const Address& addressToCall, const Functor& function, const Bytes& dataToCall) {
  ethCallInfoAllocated callInfo;
  auto& [from, to, gasLimit, gasPrice, value, functor, data] = callInfo;
  to = addressToCall;
  functor = function;
  data = dataToCall;
  return callInfo;
}


void initialize(std::unique_ptr<Options>& options,
                std::unique_ptr<DB>& db,
                std::unique_ptr<ContractManager> &contractManager,
                const std::string& dbName,
                const PrivKey& ownerPrivKey,
                const std::string& tokenName,
                const std::string& tokenSymbol,
                const uint8_t& tokenDecimals,
                const uint256_t& tokenSupply,
                bool deleteDB = true) {
  if (deleteDB) {
    if (std::filesystem::exists(dbName)) {
      std::filesystem::remove_all(dbName);
    }
  }

  options = std::make_unique<Options>(Options::fromFile(dbName));
  db = std::make_unique<DB>(dbName);
  std::unique_ptr<rdPoS> rdpos;
  contractManager = std::make_unique<ContractManager>(nullptr, db, rdpos, options, nullptr);

  if (deleteDB) {
    /// Create the contract.

    Bytes createNewERC20ContractEncoder = ABI::Encoder::encodeData(tokenName, tokenSymbol, tokenDecimals, tokenSupply);
    Bytes createNewERC20ContractData = Hex::toBytes("0xb74e5ed5");
    Utils::appendBytes(createNewERC20ContractData, createNewERC20ContractEncoder);

    TxBlock createNewERC2OTx = TxBlock(
      ProtocolContractAddresses.at("ContractManager"),
      Secp256k1::toAddress(Secp256k1::toUPub(ownerPrivKey)),
      createNewERC20ContractData,
      8080,
      0,
      0,
      0,
      0,
      0,
      ownerPrivKey
    );

    contractManager->callContract(createNewERC2OTx);
  }
}

namespace TERC20 {
  std::string testDumpPath = Utils::getTestDumpPath();
  TEST_CASE("ERC2O Class", "[contract][erc20]") {
    PrivKey ownerPrivKey(Hex::toBytes("0xe89ef6409c467285bcae9f80ab1cfeb3487cfe61ab28fb7d36443e1daa0c2867"));
    Address owner = Secp256k1::toAddress(Secp256k1::toUPub(ownerPrivKey));
    SECTION("ERC20 Class Constructor") {
      Address erc20Address;
      {
        std::unique_ptr<Options> options;
        std::unique_ptr<DB> db;
        std::unique_ptr<ContractManager> contractManager;
        std::string dbName = testDumpPath + "/erc20ClassConstructor";
        std::string tokenName = "TestToken";
        std::string tokenSymbol = "TST";
        uint8_t tokenDecimals = 18;
        uint256_t tokenSupply = 1000000000000000000;
        initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals, tokenSupply);

        erc20Address = contractManager->getContracts()[0].second;

        Bytes nameEncoder = Bytes(32, 0);
        Bytes symbolEncoder = Bytes(32, 0);
        Bytes decimalsEncoder = Bytes(32, 0);
        Bytes totalSupplyEncoder = Bytes(32, 0);

        Functor nameFunctor = ABI::FunctorEncoder::encode<void>("name");
        Functor symbolFunctor = ABI::FunctorEncoder::encode<void>("symbol");
        Functor decimalsFunctor = ABI::FunctorEncoder::encode<void>("decimals");
        Functor totalSupplyFunctor = ABI::FunctorEncoder::encode<void>("totalSupply");

        Bytes nameData = contractManager->callContract(buildCallInfo(erc20Address, nameFunctor, nameEncoder));

        auto nameDecoder = ABI::Decoder::decodeData<std::string>(nameData);
        REQUIRE(std::get<0>(nameDecoder) == tokenName);

        Bytes symbolData = contractManager->callContract(buildCallInfo(erc20Address, symbolFunctor, symbolEncoder));

        auto symbolDecoderResult = ABI::Decoder::decodeData<std::string>(symbolData);
        REQUIRE(std::get<0>(symbolDecoderResult) == tokenSymbol);

        Bytes decimalsData = contractManager->callContract(buildCallInfo(erc20Address, decimalsFunctor, decimalsEncoder));

        auto decimalsDecoder = ABI::Decoder::decodeData<uint256_t>(decimalsData);
        REQUIRE(std::get<0>(decimalsDecoder) == 18);

        Bytes totalSupplyData = contractManager->callContract(buildCallInfo(erc20Address, totalSupplyFunctor, totalSupplyEncoder));

        auto totalSupplyDecoder = ABI::Decoder::decodeData<uint256_t>(totalSupplyData);
        REQUIRE(std::get<0>(totalSupplyDecoder) == tokenSupply);

        Bytes balanceOfData = contractManager->callContract(buildCallInfo(erc20Address, totalSupplyFunctor, totalSupplyEncoder));

        auto balanceOfDecoder = ABI::Decoder::decodeData<uint256_t>(balanceOfData);
        REQUIRE(std::get<0>(balanceOfDecoder) == tokenSupply);
      }

      std::unique_ptr<Options> options;
      std::unique_ptr<DB> db;
      std::unique_ptr<ContractManager> contractManager;
      std::string dbName = testDumpPath + "/erc20ClassConstructor";
      std::string tokenName = "TestToken";
      std::string tokenSymbol = "TST";
      uint8_t tokenDecimals = 18;
      uint256_t tokenSupply = 1000000000000000000;
      initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals, tokenSupply, false);

      REQUIRE(erc20Address == contractManager->getContracts()[0].second);
    
      Bytes nameEncoder = Bytes(32, 0);
      Bytes symbolEncoder = Bytes(32, 0);
      Bytes decimalsEncoder = Bytes(32, 0);
      Bytes totalSupplyEncoder = Bytes(32, 0);

      Functor nameFunctor = ABI::FunctorEncoder::encode<void>("name");
      Functor symbolFunctor = ABI::FunctorEncoder::encode<void>("symbol");
      Functor decimalsFunctor = ABI::FunctorEncoder::encode<void>("decimals");
      Functor totalSupplyFunctor = ABI::FunctorEncoder::encode<void>("totalSupply");

      Bytes nameData = contractManager->callContract(buildCallInfo(erc20Address, nameFunctor, nameEncoder));

      auto nameDecoder = ABI::Decoder::decodeData<std::string>(nameData);
      REQUIRE(std::get<0>(nameDecoder) == tokenName);

      Bytes symbolData = contractManager->callContract(buildCallInfo(erc20Address, symbolFunctor, symbolEncoder));

      auto symbolDecoder = ABI::Decoder::decodeData<std::string>(symbolData);
      REQUIRE(std::get<0>(symbolDecoder) == tokenSymbol);

      Bytes decimalsData = contractManager->callContract(buildCallInfo(erc20Address, decimalsFunctor, decimalsEncoder));

      auto decimalsDecoder = ABI::Decoder::decodeData<uint256_t>(decimalsData);
      REQUIRE(std::get<0>(decimalsDecoder) == 18);

      Bytes totalSupplyData = contractManager->callContract(buildCallInfo(erc20Address, totalSupplyFunctor, totalSupplyEncoder));

      auto totalSupplyDecoder = ABI::Decoder::decodeData<uint256_t>(totalSupplyData);
      REQUIRE(std::get<0>(totalSupplyDecoder) == tokenSupply);

      Bytes balanceOfData = contractManager->callContract(buildCallInfo(erc20Address, totalSupplyFunctor, totalSupplyEncoder));

      auto balanceOfDecoder = ABI::Decoder::decodeData<uint256_t>(balanceOfData);
      REQUIRE(std::get<0>(balanceOfDecoder) == tokenSupply);
    }

    SECTION("ERC20 transfer()") {
      Address erc20Address;
      Address destinationOfTransactions(Utils::randBytes(20));

      {
        std::unique_ptr<Options> options;
        std::unique_ptr<DB> db;
        std::unique_ptr<ContractManager> contractManager;
        std::string dbName = testDumpPath + "/erc20ClassTransfer";
        std::string tokenName = "TestToken";
        std::string tokenSymbol = "TST";
        uint8_t tokenDecimals = 18;
        uint256_t tokenSupply = 1000000000000000000;
        initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                   tokenSupply);

        erc20Address = contractManager->getContracts()[0].second;

        Bytes getBalanceMeEncoder = ABI::Encoder::encodeData(owner);
        Functor getBalanceMeFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

        Bytes getBalanceDestinationEncoder = ABI::Encoder::encodeData(destinationOfTransactions);
        Functor getBalanceDestinationFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

        Bytes transferData = Hex::toBytes("0xa9059cbb");

        Bytes transferEncoder = ABI::Encoder::encodeData(destinationOfTransactions, static_cast<uint256_t>(500000000000000000));
        Utils::appendBytes(transferData, transferEncoder);
        TxBlock transferTx(
          erc20Address,
          owner,
          transferData,
          8080,
          0,
          0,
          0,
          0,
          0,
          ownerPrivKey
        );

        auto randomPrivKey = PrivKey(Utils::randBytes(32));
        TxBlock transferTxThrows = TxBlock(
          erc20Address,
          Secp256k1::toAddress(Secp256k1::toUPub(randomPrivKey)),
          transferData,
          8080,
          0,
          0,
          0,
          0,
          0,
          randomPrivKey
        );

        REQUIRE_THROWS(contractManager->validateCallContractWithTx(transferTxThrows.txToCallInfo()));
        contractManager->validateCallContractWithTx(transferTx.txToCallInfo());

        Bytes getBalanceMeResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceMeFunctor, getBalanceMeEncoder));

        auto getBalanceMeDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
        REQUIRE(std::get<0>(getBalanceMeDecoder) == 1000000000000000000);

        Bytes getBalanceDestinationResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceDestinationFunctor, getBalanceDestinationEncoder));

        auto getBalanceDestinationDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
        REQUIRE(std::get<0>(getBalanceDestinationDecoder) == 0);

        REQUIRE_THROWS(contractManager->callContract(transferTxThrows));
        contractManager->callContract(transferTx);

        getBalanceMeResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceMeFunctor, getBalanceMeEncoder));

        auto getBalanceMeDecoder2 = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
        REQUIRE(std::get<0>(getBalanceMeDecoder2) == 500000000000000000);

        getBalanceDestinationResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceDestinationFunctor, getBalanceDestinationEncoder));

        auto getBalanceDestinationDecoder2 = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
        REQUIRE(std::get<0>(getBalanceDestinationDecoder2) == 500000000000000000);

      }
      std::unique_ptr<Options> options;
      std::unique_ptr<DB> db;
      std::unique_ptr<ContractManager> contractManager;
      std::string dbName = testDumpPath + "/erc20ClassTransfer";
      std::string tokenName = "TestToken";
      std::string tokenSymbol = "TST";
      uint8_t tokenDecimals = 18;
      uint256_t tokenSupply = 1000000000000000000;
      initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                   tokenSupply, false);

      REQUIRE(erc20Address == contractManager->getContracts()[0].second);

      Bytes getBalanceMeEncoder = ABI::Encoder::encodeData(owner);
      Functor getBalanceMeFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

      Bytes getBalanceDestinationEncoder = ABI::Encoder::encodeData(destinationOfTransactions);
      Functor getBalanceDestinationFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

      Bytes getBalanceMeResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceMeFunctor, getBalanceMeEncoder));

      auto getBalanceMeDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
      REQUIRE(std::get<0>(getBalanceMeDecoder) == 500000000000000000);

      Bytes getBalanceDestinationResult = contractManager->callContract(buildCallInfo(erc20Address, getBalanceDestinationFunctor, getBalanceDestinationEncoder));

      auto getBalanceDestinationDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
      REQUIRE(std::get<0>(getBalanceDestinationDecoder) == 500000000000000000);
    }

    SECTION("ERC20 Approve") {
      Address erc20Address;
      Address destinationOfApproval(Utils::randBytes(20));

      {
        std::unique_ptr<Options> options;
        std::unique_ptr<DB> db;
        std::unique_ptr<ContractManager> contractManager;
        std::string dbName = testDumpPath + "/erc20ClassApprove";
        std::string tokenName = "TestToken";
        std::string tokenSymbol = "TST";
        uint8_t tokenDecimals = 18;
        uint256_t tokenSupply = 1000000000000000000;
        initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                   tokenSupply);

        erc20Address = contractManager->getContracts()[0].second;

        Bytes getAllowanceEncoder = ABI::Encoder::encodeData(owner, destinationOfApproval);
        Functor getAllowanceFunctor = ABI::FunctorEncoder::encode<Address,Address>("allowance");

        Bytes approveEncoder = ABI::Encoder::encodeData(destinationOfApproval, static_cast<uint256_t>(500000000000000000));
        Bytes approveData = Hex::toBytes("0x095ea7b3");
        Utils::appendBytes(approveData, approveEncoder);
        TxBlock approveTx(
          erc20Address,
          owner,
          approveData,
          8080,
          0,
          0,
          0,
          0,
          0,
          ownerPrivKey
        );

        contractManager->validateCallContractWithTx(approveTx.txToCallInfo());

        Bytes getAllowanceResult = contractManager->callContract(buildCallInfo(erc20Address, getAllowanceFunctor, getAllowanceEncoder));

        auto getAllowanceDecoder = ABI::Decoder::decodeData<uint256_t>(getAllowanceResult);
        REQUIRE(std::get<0>(getAllowanceDecoder) == 0);

        contractManager->callContract(approveTx);

        getAllowanceResult = contractManager->callContract(buildCallInfo(erc20Address, getAllowanceFunctor, getAllowanceEncoder));

        getAllowanceDecoder = ABI::Decoder::decodeData<uint256_t>(getAllowanceResult);
        REQUIRE(std::get<0>(getAllowanceDecoder) == 500000000000000000);

      }

      std::unique_ptr<Options> options;
      std::unique_ptr<DB> db;
      std::unique_ptr<ContractManager> contractManager;
      std::string dbName = testDumpPath + "/erc20ClassApprove";
      std::string tokenName = "TestToken";
      std::string tokenSymbol = "TST";
      uint8_t tokenDecimals = 18;
      uint256_t tokenSupply = 1000000000000000000;
      initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                 tokenSupply, false);

      REQUIRE(erc20Address == contractManager->getContracts()[0].second);

      Bytes getAllowanceEncoder = ABI::Encoder::encodeData(owner, destinationOfApproval);
      Functor getAllowanceFunctor = ABI::FunctorEncoder::encode<Address,Address>("allowance");

      Bytes getAllowanceResult = contractManager->callContract(buildCallInfo(erc20Address, getAllowanceFunctor, getAllowanceEncoder));

      auto getAllowanceDecoder = ABI::Decoder::decodeData<uint256_t>(getAllowanceResult);
      REQUIRE(std::get<0>(getAllowanceDecoder) == 500000000000000000);
    }

    SECTION("ERC20 transferFrom") {
      PrivKey destinationOfApprovalPrivKey(Utils::randBytes(32));
      Address destinationOfApproval(Secp256k1::toAddress(Secp256k1::toUPub(destinationOfApprovalPrivKey)));
      Address erc20Address;
      {
        std::unique_ptr<Options> options;
        std::unique_ptr<DB> db;
        std::unique_ptr<ContractManager> contractManager;
        std::string dbName = testDumpPath + "/erc20ClassTransferFrom";
        std::string tokenName = "TestToken";
        std::string tokenSymbol = "TST";
        uint8_t tokenDecimals = 18;
        uint256_t tokenSupply = 1000000000000000000;
        initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                   tokenSupply);

        erc20Address = contractManager->getContracts()[0].second;

        Bytes approveEncoder = ABI::Encoder::encodeData(destinationOfApproval, static_cast<uint256_t>(500000000000000000));
        Bytes approveData = Hex::toBytes("0x095ea7b3");
        Utils::appendBytes(approveData, approveEncoder);
        TxBlock approveTx(
          erc20Address,
          owner,
          approveData,
          8080,
          0,
          0,
          0,
          0,
          0,
          ownerPrivKey
        );

        contractManager->callContract(approveTx);

        Bytes transferFromEncoder = ABI::Encoder::encodeData(owner, destinationOfApproval, static_cast<uint256_t>(500000000000000000));
        Bytes transferFromBytes = Hex::toBytes("0x23b872dd");
        Utils::appendBytes(transferFromBytes, transferFromEncoder);
        TxBlock transferFromTx(
          erc20Address,
          destinationOfApproval,
          transferFromBytes,
          8080,
          0,
          0,
          0,
          0,
          0,
          destinationOfApprovalPrivKey
        );

        auto randomPrivKey = PrivKey(Utils::randBytes(32));
        TxBlock transferFromTxThrows = TxBlock(
          erc20Address,
          Secp256k1::toAddress(Secp256k1::toUPub(randomPrivKey)),
          transferFromBytes,
          8080,
          0,
          0,
          0,
          0,
          0,
          randomPrivKey
        );

        REQUIRE_THROWS(contractManager->validateCallContractWithTx(transferFromTxThrows.txToCallInfo()));
        contractManager->validateCallContractWithTx(transferFromTx.txToCallInfo());

        Bytes getBalanceMeEncoder = ABI::Encoder::encodeData(owner);
        Functor getBalanceMeFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

        Bytes getBalanceMeResult = contractManager->callContract(buildCallInfo(
          erc20Address, getBalanceMeFunctor, getBalanceMeEncoder
        ));

        auto getBalanceMeDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
        REQUIRE(std::get<0>(getBalanceMeDecoder) == 1000000000000000000);

        Bytes getBalanceDestinationEncoder = ABI::Encoder::encodeData(destinationOfApproval);
        Functor getBalanceDestinationFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

        Bytes getBalanceDestinationResult = contractManager->callContract(buildCallInfo(
          erc20Address,
          getBalanceDestinationFunctor,
          getBalanceDestinationEncoder
        ));

        auto getBalanceDestinationDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
        REQUIRE(std::get<0>(getBalanceDestinationDecoder) == 0);

        REQUIRE_THROWS(contractManager->callContract(transferFromTxThrows));
        contractManager->callContract(transferFromTx);

        getBalanceMeResult = contractManager->callContract(buildCallInfo(
          erc20Address, getBalanceMeFunctor, getBalanceMeEncoder
        ));

        getBalanceMeDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
        REQUIRE(std::get<0>(getBalanceMeDecoder) == 500000000000000000);

        getBalanceDestinationResult = contractManager->callContract(buildCallInfo(
          erc20Address,
          getBalanceDestinationFunctor,
          getBalanceDestinationEncoder
        ));
        getBalanceDestinationDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
        REQUIRE(std::get<0>(getBalanceDestinationDecoder) == 500000000000000000);
      }

      std::unique_ptr<Options> options;
      std::unique_ptr<DB> db;
      std::unique_ptr<ContractManager> contractManager;
      std::string dbName = testDumpPath + "/erc20ClassTransferFrom";
      std::string tokenName = "TestToken";
      std::string tokenSymbol = "TST";
      uint8_t tokenDecimals = 18;
      uint256_t tokenSupply = 1000000000000000000;
      initialize(options, db, contractManager, dbName, ownerPrivKey, tokenName, tokenSymbol, tokenDecimals,
                 tokenSupply, false);

      Bytes getBalanceMeEncoder = ABI::Encoder::encodeData(owner);
      Functor getBalanceMeFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

      Bytes getBalanceMeResult = contractManager->callContract(buildCallInfo(
        erc20Address, getBalanceMeFunctor, getBalanceMeEncoder
      ));

      auto getBalanceMeDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceMeResult);
      REQUIRE(std::get<0>(getBalanceMeDecoder) == 500000000000000000);

      Bytes getBalanceDestinationEncoder = ABI::Encoder::encodeData(destinationOfApproval);
      Functor getBalanceDestinationFunctor = ABI::FunctorEncoder::encode<Address>("balanceOf");

      Bytes getBalanceDestinationResult = contractManager->callContract(buildCallInfo(
        erc20Address,
        getBalanceDestinationFunctor,
        getBalanceDestinationEncoder
      ));

      auto getBalanceDestinationDecoder = ABI::Decoder::decodeData<uint256_t>(getBalanceDestinationResult);
      REQUIRE(std::get<0>(getBalanceDestinationDecoder) == 500000000000000000);
    }
  }
}
