#!/bin/bash


# Check if the user is running this script from the main directory of the project
if [ ! -f "scripts/AIO-setup.sh" ]; then
  echo "Please run this script from the main directory of the project"
  exit 1
fi


cd build_local_testnet

cmake --build . --target orbitersdkd -- -j $(($(nproc) - 1))

cd ..

echo "Binaries Compiled"
echo "Updating Binaries in local_testnet"

cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal1
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal2
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal3
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal4
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal5
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_normal6
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_validator1
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_validator2
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_validator3
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_validator4
cp build_local_testnet/src/bins/orbitersdkd/orbitersdkd local_testnet/local_testnet_validator5
cp build_local_testnet/src/bins/orbitersdkd-discovery/orbitersdkd-discovery local_testnet/local_testnet_discovery