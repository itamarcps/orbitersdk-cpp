#!/bin/bash


# Check if the user is running this script from the main directory of the project
if [ ! -f "scripts/AIO-setup.sh" ]; then
  echo "Please run this script from the main directory of the project"
  exit 1
fi


rm -rf local_testnet/local_testnet_normal1/blockchain/database
rm -rf local_testnet/local_testnet_normal2/blockchain/database
rm -rf local_testnet/local_testnet_normal3/blockchain/database
rm -rf local_testnet/local_testnet_normal4/blockchain/database
rm -rf local_testnet/local_testnet_normal5/blockchain/database
rm -rf local_testnet/local_testnet_normal6/blockchain/database
rm -rf local_testnet/local_testnet_validator1/blockchain/database
rm -rf local_testnet/local_testnet_validator2/blockchain/database
rm -rf local_testnet/local_testnet_validator3/blockchain/database
rm -rf local_testnet/local_testnet_validator4/blockchain/database
rm -rf local_testnet/local_testnet_validator5/blockchain/database

tar -xvf local_testnet.tar.gz
echo "Local testnet reset to snapshot"

