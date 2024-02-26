#ifndef EC_RECOVER_PRECOMPILE_HPP
#define EC_RECOVER_PRECOMPILE_HPP


#include <evmc/evmc.hpp>
#include <secp256k1.h>

#include "utils/ecdsa.h"
#include "../contract/abi.h"

using namespace evmc::literals;
const auto ECRECOVER_ADDRESS = 0x0000000000000000000000000000100000000001_address;

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
      std::cout << "Getting the data!" << std::endl;
      Bytes ecrecoverBytes(msg.input_data + 4, msg.input_data + msg.input_size);
      std::cout << "Trying to recover the data!" << std::endl;
      std::cout << "ecRecovers: " << Hex::fromBytes(ecrecoverBytes).get() << std::endl;
      std::cout << "ecRecoverSize: " << ecrecoverBytes.size() << std::endl;
      // Each data member has a offset of 32 bytes
      const auto& msgHash = Hash(BytesArrView(ecrecoverBytes.data(), 32));
      const auto& v = uint8_t(Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 32, 32)));
      const auto& r = Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 64, 32));
      const auto& s = Utils::bytesToUint256(BytesArrView(ecrecoverBytes.data() + 96, 32));
      std::cout << "Checking if V is valid" << std::endl;
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
      std::cout << "creating signature" << std::endl;
      auto sig = Secp256k1::makeSig(r, s, parity);
      // Recover to address!
      std::cout << "recovering address" << std::endl;
      auto addr = Secp256k1::toAddress(Secp256k1::recover(sig, msgHash));
      std::cout << "Derived address: " << addr.hex(true) << std::endl;
      // Uhhhhhhhhhhhh funny moment, evmc::Result uses a data pointer* and the VM is required to free it, but we are not a VM so what happens?
      // We instead create a std::array<32> and make the pointer points to it, and annotate it into the Host so the host can free it
      BytesArr<32> addrBytes = {};
      // As address has 20 bytes, we need to copy the last 20 bytes of the address to the 12th byte of the array
      std::cout << "copying address" << std::endl;
      std::copy(addr.cbegin(), addr.cend(), addrBytes.begin() + 12);
      addrs.push_back(addrBytes);
      std::cout << "returning..." << Hex::fromBytes(addrs.back()).get() << std::endl;
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
}




#endif // EC_RECOVER_PRECOMPILE_HPP