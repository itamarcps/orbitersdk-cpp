#include "ecrecoverprecompile.h"


namespace Precompile {
  evmc::Result ecrecover(const evmc_message& msg, std::vector<std::array<uint8_t, 32>>& addrs) noexcept {
    // We know that V is always a 32 bytes value containing either 27 or 28, extract this into a uint8_t, V is big endian
    evmc::Result result;
    try {
      // Check if the input data matches the required for ecrecover
      if (msg.input_size != 132) {
        std::cerr << "Invalid input size for ecrecover precompile: " << msg.input_size << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      // Convert them to bytes to use ABI decoder then use Secp256k1::recover, skip functor as we don't need it
      BytesArrView ecrecoverBytes(msg.input_data + 4, msg.input_data + msg.input_size);
      // Each data member has a offset of 32 bytes
      const auto msgHash = Hash(BytesArrView(ecrecoverBytes.data(), 32));
      const auto v = uint8_t(Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 32, 32)));
      const auto r = Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 64, 32));
      const auto s = Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 96, 32));
      // Check if V is either 27 or 28
      if (v != 27 && v != 28) {
        std::cerr << "Invalid V value for ecrecover precompile V: " << v << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      const bool parity = v == 28;
      bool valid = Secp256k1::verifySig(r, s, parity);
      if (!valid) {
        std::cerr << "Invalid signature for ecrecover precompile" << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      // Create the signature
      auto sig = Secp256k1::makeSig(r, s, parity);
      // Recover to address!
      auto addr = Secp256k1::toAddress(Secp256k1::recover(sig, msgHash));
      std::cout << "ecrecover msghash: " << msgHash.hex() << std::endl;
      std::cout << "ecrecover v: " << Hex::fromBytes(Utils::uint256ToBytes(v)) << std::endl;
      std::cout << "ecrecover r: " << Hex::fromBytes(Utils::uint256ToBytes(r)) << std::endl;
      std::cout << "ecrecover s: " << Hex::fromBytes(Utils::uint256ToBytes(s)) << std::endl;
      std::cout << "ecrecover addr: " << addr.hex() << std::endl;
      // Uhhhhhhhhhhhh funny moment, evmc::Result uses a data pointer* and the VM is required to free it, but we are not a VM so what happens?
      // We instead create a std::array<32> and make the pointer points to it, and annotate it into the Host so the host can free it
      BytesArr<32> addrBytes = {};
      // As address has 20 bytes, we need to copy the last 20 bytes of the address to the 12th byte of the array
      std::copy(addr.cbegin(), addr.cend(), addrBytes.begin() + 12);
      addrs.push_back(addrBytes);
      result.status_code = EVMC_SUCCESS;
      result.output_data = addrs.back().data();
      result.output_size = 32;
      result.gas_left = msg.gas;
      return result;
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
      result.status_code = EVMC_REVERT;
      result.output_size = 0;
      return result;
    }
  }

  evmc::Result packAndHash(const evmc_message& msg, std::vector<std::array<uint8_t, 32>>& hashs) noexcept {
    evmc::Result result;
    try {
      // Check if the input data matches the required for ecrecover
      if (msg.input_size != 68) {
        std::cerr << "Invalid input size for ecrecover precompile: " << msg.input_size << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      // we need to pack an uint256+address (52 bytes)
      BytesArrView packBytes(msg.input_data, msg.input_data + msg.input_size);
      std::cout << "packBytes.subspan(4).size(): " << packBytes.subspan(4).size() << std::endl;
      auto resultTlp = ABI::Decoder::decodeData<uint256_t,Address>(packBytes.subspan(4));
      const auto& tokenId = std::get<0>(resultTlp);
      const auto& user = std::get<1>(resultTlp);
      std::cout << "tokenId: " << tokenId << std::endl;
      std::cout << "user: " << user.hex() << std::endl;
      Bytes value;
      value.reserve(52); // 32 bytes for tokenId and 20 bytes for user
      Utils::appendBytes(value, Utils::uint256ToBytes(tokenId));
      Utils::appendBytes(value, user.asBytes());
      std::cout << "packAndHash pack: " << Hex::fromBytes(value) << std::endl;
      auto keccakHash = Utils::sha3(value);
      std::cout << "packAndHash keccakHash: " << keccakHash.hex() << std::endl;
      std::array<uint8_t, 32> keccakHashArr;
      std::copy(keccakHash.cbegin(), keccakHash.cend(), keccakHashArr.begin());
      hashs.push_back(keccakHashArr);
      result.status_code = EVMC_SUCCESS;
      result.output_data = hashs.back().data();
      result.output_size = 32;
      result.gas_left = msg.gas;
      std::cout << "PACKED: "  << keccakHash.hex() << std::endl;
      return result;
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
      result.status_code = EVMC_REVERT;
      result.output_size = 0;
      return result;
    }
  }
  evmc::Result keccakSolSign(const evmc_message& msg, std::vector<std::array<uint8_t, 32>>& hashs) noexcept {
    evmc::Result result;
    try {
      // Check if the input data matches the required for ecrecover
      if (msg.input_size != 36) {
        std::cerr << "Invalid input size for ecrecover precompile: " << msg.input_size << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      // we need to pack an uint256+address (52 bytes)
      BytesArrView packBytes(msg.input_data, msg.input_data + msg.input_size);
      auto resultTlp = ABI::Decoder::decodeData<Hash>(packBytes.subspan(4));
      const auto& hash = std::get<0>(resultTlp);
      Bytes value;
      value.insert(value.end(), 0x19);
      std::string ethereumSignedMessage = "Ethereum Signed Message:";
      Utils::appendBytes(value, ethereumSignedMessage);
      value.insert(value.end(), '\n');
      Utils::appendBytes(value, std::to_string(32));
      Utils::appendBytes(value, hash);
      std::cout << "keccakSolSign pack: " << Hex::fromBytes(value) << std::endl;
      auto keccakHash = Utils::sha3(value);
      std::array<uint8_t, 32> keccakHashArr;
      std::copy(keccakHash.cbegin(), keccakHash.cend(), keccakHashArr.begin());
      hashs.push_back(keccakHashArr);
      result.status_code = EVMC_SUCCESS;
      result.output_data = hashs.back().data();
      result.output_size = 32;
      result.gas_left = msg.gas;
      return result;
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
      result.status_code = EVMC_REVERT;
      result.output_size = 0;
      return result;
    }
  }

  evmc::Result keccak(const evmc_message& msg, std::vector<std::array<uint8_t, 32>>& hashs) noexcept {
    evmc::Result result;
    try {
      // Check if the input data matches the required for ecrecover
      if (msg.input_size > 4) {
        std::cerr << "Invalid input size for ecrecover precompile: " << msg.input_size << std::endl;
        result.status_code = EVMC_REVERT;
        result.output_size = 0;
        return result;
      }
      // we need to pack an uint256+address (52 bytes)
      BytesArrView packBytes(msg.input_data, msg.input_data + msg.input_size);
      auto resultTlp = ABI::Decoder::decodeData<Bytes>(packBytes.subspan(4));
      const auto& data = std::get<0>(resultTlp);
      auto keccakHash = Utils::sha3(data);
      std::array<uint8_t, 32> keccakHashArr;
      std::copy(keccakHash.cbegin(), keccakHash.cend(), keccakHashArr.begin());
      hashs.push_back(keccakHashArr);
      result.status_code = EVMC_SUCCESS;
      result.output_data = hashs.back().data();
      result.output_size = 32;
      result.gas_left = msg.gas;
      return result;
    } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
      result.status_code = EVMC_REVERT;
      result.output_size = 0;
      return result;
    }
  }
}