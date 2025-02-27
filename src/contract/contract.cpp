/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include "contract.h"

RandomGen* ContractGlobals::randomGen_ = nullptr;
Address ContractGlobals::coinbase_ = Address(Hex::toBytes("0x0000000000000000000000000000000000000000"));
Hash ContractGlobals::blockHash_ = Hash();
uint64_t ContractGlobals::blockHeight_ = 0;
uint64_t ContractGlobals::blockTimestamp_ = 0;

