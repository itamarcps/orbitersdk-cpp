#!/bin/bash


# Check if the user is running this script from the main directory of the project
if [ ! -f "scripts/AIO-setup.sh" ]; then
  echo "Please run this script from the main directory of the project"
  exit 1
fi


rm -rf local_testnet/local_testnet_normal1/blockchain/options.json
rm -rf local_testnet/local_testnet_normal2/blockchain/options.json
rm -rf local_testnet/local_testnet_normal3/blockchain/options.json
rm -rf local_testnet/local_testnet_normal4/blockchain/options.json
rm -rf local_testnet/local_testnet_normal5/blockchain/options.json
rm -rf local_testnet/local_testnet_normal6/blockchain/options.json
rm -rf local_testnet/local_testnet_validator1/blockchain/options.json
rm -rf local_testnet/local_testnet_validator2/blockchain/options.json
rm -rf local_testnet/local_testnet_validator3/blockchain/options.json
rm -rf local_testnet/local_testnet_validator4/blockchain/options.json
rm -rf local_testnet/local_testnet_validator5/blockchain/options.json

tar -xvf local_options.tar.gz
echo "Local testnet reset to snapshot"
