#include "core/utils.h"
#include "core/transaction.h"
#include "core/block.h"
#include <thread>


void runBenchmark() {
  uint64_t nThread = std::thread::hardware_concurrency();
  std::string exampleTransaction = Utils::hexToBytes("0xf86e8085012a05f2008252089421b782f9bf82418a42d034517cb6bf00b4c17612880de0b6b3a764000080824544a00d5d36ed2f2cdeda4f85eb30a3a32ee167ba904a0f037200774916d0f7c73414a066731ef223adbf8d2e5d5f5e758b036db127589ff2e1c7c100910fb9ccba3488");
  //std::cout << "Running 500000 transactions per thread (" << nThread << ") total: " << 500000 * nThread  << std::endl;
  //{
  //  std::atomic<uint64_t> counter = 0;
  //  std::vector<std::thread> threads;
  //  auto start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
  //  for (uint64_t i = 0; i < nThread; ++i) {
  //    threads.push_back(std::thread([&]() {
  //      for (uint64_t i = 0; i < 500000; ++i) {
  //        Tx::Base tx(exampleTransaction, false);
  //        ++counter;
  //      }
  //    }));
  //  }
  //  for (auto& thread : threads) {
  //    thread.join();
  //  }
  //  auto end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
  //  std::cout << "Running time: " << end.count() - start.count() << "ms" << std::endl;
  //  std::cout << "Transactions per second: " << counter / ((end.count() - start.count()) / 1000) << std::endl;
//
  //}

  std::cout << "Creating block with 200 000 transactions, using one thread" << std::endl;
  std::string blockBytes;
  {
    auto start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    auto tx = Tx::Base(exampleTransaction, false);
    Block block(0, 1656356645000000, 0);
    for (uint64_t i = 0; i < 200000; ++i) {
      if (i % 25000 == 0) {
        std::cout << i << " transactions appended" << std::endl;
      }
      block.appendTx(tx);
    }
    
    block.finalizeBlock();
    block.indexTxs();

    auto end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    std::cout << "Block created in " << end.count() - start.count() << "ms" << std::endl;
  
    std::cout << "Block hash: " << Utils::bytesToHex(block.getBlockHash()) << std::endl;
  
    std::cout << "Block size: " << double(block.blockSize()) / 1000000 << "MB" << std::endl;
    std::cout << "Serializing block using one thread." << std::endl;
    start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    blockBytes = block.serializeToBytes(false);
    end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    std::cout << "Block serialized in " << end.count() - start.count() << "ms" << std::endl;
  }

  // Load block from bytes
  std::cout << "Serializing block from bytes (200k tx) using " << nThread << " threads (checking signature)" << std::endl;
  {
    auto start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    Block block2(blockBytes, false);
    auto end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    std::cout << "Block loaded in " << end.count() - start.count() << "ms" << std::endl;
    blockBytes = block2.serializeToBytes(true);
  }

  std::cout << "Serializing block from bytes (200k tx) using " << nThread << " threads (not checking signature)" << std::endl;
  {
    auto start = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    Block block2(blockBytes, true);
    auto end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now().time_since_epoch());
    std::cout << "Block loaded in " << end.count() - start.count() << "ms" << std::endl;
  }

}