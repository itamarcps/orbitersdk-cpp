#include "abci.h"
/*
 *   TxBlock(const Address to, const Address from, const Bytes &data,
          const uint64_t chainId, const uint256_t nonce, const uint256_t value,
          const uint256_t maxPriorityFeePerGas, const uint256_t maxFeePerGas,
          const uint256_t gasLimit, const PrivKey privKey);
 */
int main() {
  CometBlockchain comet;
  comet.startChain();

  return 0;
}