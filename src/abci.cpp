#include "abci.h"

uint64_t TimestampToMicroseconds(const google::protobuf::Timestamp& timestamp) {
  return timestamp.seconds() * 1000000 + timestamp.nanos() / 1000;
}

google::protobuf::Timestamp MicrosecondsToTimestamp(uint64_t microseconds) {
  google::protobuf::Timestamp timestamp;
  timestamp.set_seconds(microseconds / 1000000);
  timestamp.set_nanos((microseconds % 1000000) * 1000);
  return timestamp;
}

Status ABCIServiceImplementation::Echo(ServerContext* context, const tendermint::abci::RequestEcho* request, tendermint::abci::ResponseEcho* response) {
  std::cout << "ABCI::Echo" << std::endl;
  response->set_message(request->message());
  return Status::OK;
}

Status ABCIServiceImplementation::Flush(ServerContext* context, const tendermint::abci::RequestFlush* request, tendermint::abci::ResponseFlush* response) {
  std::cout << "ABCI::Flush" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::Info(ServerContext* context, const tendermint::abci::RequestInfo* request, tendermint::abci::ResponseInfo* response) {
  std::cout << "ABCI::Info" << std::endl;
  response->set_data("OrbiterSDK");
  response->set_version("OrbiterSDK/cpp/linux_x86-64/0.1.2");
  response->set_app_version(012);
  if (!this->blockchain_.initialized()) {
    response->set_last_block_height(0);
  } else {
    response->set_last_block_height(this->blockchain_.getBestBlockHeight());
    response->set_last_block_app_hash(this->blockchain_.getBestBlockHash().hex());
  }

  return Status::OK;
}

Status ABCIServiceImplementation::CheckTx(ServerContext* context, const tendermint::abci::RequestCheckTx* request, tendermint::abci::ResponseCheckTx* response) {
  std::cout << "ABCI::CheckTx" << std::endl;
  this->blockchain_.checkTx(request, response);
  return Status::OK;
}

Status ABCIServiceImplementation::Query(ServerContext* context, const tendermint::abci::RequestQuery* request, tendermint::abci::ResponseQuery* response) {
  std::cout << "ABCI::Query" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::Commit(ServerContext* context, const tendermint::abci::RequestCommit* request, tendermint::abci::ResponseCommit* response) {
  std::cout << "ABCI::Commit" << std::endl;
  this->blockchain_.commit();
  return Status::OK;
}

Status ABCIServiceImplementation::InitChain(ServerContext* context, const tendermint::abci::RequestInitChain* request, tendermint::abci::ResponseInitChain* response) {
  std::cout << "ABCI::InitChain" << std::endl;
  response->set_app_hash(Utils::sha3(Utils::stringToBytes("OrbiterSDK")).hex());
  if (!this->blockchain_.initialized()) {
    this->blockchain_.initializeBlockchain();
  }
  return Status::OK;
}

Status ABCIServiceImplementation::ListSnapshots(ServerContext* context, const tendermint::abci::RequestListSnapshots* request, tendermint::abci::ResponseListSnapshots* response) {
  std::cout << "ABCI::ListSnapshots" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::OfferSnapshot(ServerContext* context, const tendermint::abci::RequestOfferSnapshot* request, tendermint::abci::ResponseOfferSnapshot* response) {
  std::cout << "ABCI::OfferSnapshot" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::LoadSnapshotChunk(ServerContext* context, const tendermint::abci::RequestLoadSnapshotChunk* request, tendermint::abci::ResponseLoadSnapshotChunk* response) {
  std::cout << "ABCI::LoadSnapshotChunk" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::ApplySnapshotChunk(ServerContext* context, const tendermint::abci::RequestApplySnapshotChunk* request, tendermint::abci::ResponseApplySnapshotChunk* response) {
  std::cout << "ABCI::ApplySnapshotChunk" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::PrepareProposal(ServerContext* context, const tendermint::abci::RequestPrepareProposal* request, tendermint::abci::ResponsePrepareProposal* response) {
  std::cout << "ABCI::PrepareProposal" << std::endl;
  this->blockchain_.prepareProposal(request, response);
  return Status::OK;
}

Status ABCIServiceImplementation::ProcessProposal(ServerContext* context, const tendermint::abci::RequestProcessProposal* request, tendermint::abci::ResponseProcessProposal* response) {
  std::cout << "ABCI::ProcessProposal" << std::endl;
  std::cout << "Processing Proposal for block height: " << request->height() << " timestamp " << google::protobuf::util::TimeUtil::ToString(request->time()) << std::endl;
  response->set_status(tendermint::abci::ResponseProcessProposal_ProposalStatus_ACCEPT);
  return Status::OK;
}

Status ABCIServiceImplementation::ExtendVote(ServerContext* context, const tendermint::abci::RequestExtendVote* request, tendermint::abci::ResponseExtendVote* response) {
  std::cout << "ABCI::ExtendVotes" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::VerifyVoteExtension(ServerContext* context, const tendermint::abci::RequestVerifyVoteExtension* request, tendermint::abci::ResponseVerifyVoteExtension* response) {
  std::cout << "ABCI::VerifyVoteExtension" << std::endl;
  return Status::OK;
}

Status ABCIServiceImplementation::FinalizeBlock(ServerContext* context, const tendermint::abci::RequestFinalizeBlock* request, tendermint::abci::ResponseFinalizeBlock* response) {
  std::cout << "ABCI::FinalizeBlock" << std::endl;
  this->blockchain_.finalizeBlock(request, response);
  return Status::OK;
}

CometBlockchain::CometBlockchain() {
  /// Check if the blockchain was previously initialized
  blockchainPath_ = std::filesystem::current_path().string() + std::string("/cosmos-blockchain");
  if (std::filesystem::exists(blockchainPath_)) {
    this->initializeBlockchain();
  }
}

void CometBlockchain::startChain() {
  unsigned short port = 26658;
  std::string server_address(std::string("0.0.0.0:") + std::to_string(port));
  std::cout << "Starting Comet Blockchain on port: " << server_address << std::endl;
  this->abci_ = std::make_shared<ABCIServiceImplementation>(*this);
  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(abci_.get());
  this->grpcServer = builder.BuildAndStart();
  std::cout << "Comet Blockchain listening on " << server_address << std::endl;
  this->grpcServer->Wait();
  std::cout << "Comet Blockchain stopped" << std::endl;
  return;
}

uint64_t CometBlockchain::getBestBlockHeight() const {
  return this->storage_->currentChainSize() - 1;
}

Hash CometBlockchain::getBestBlockHash() const {
  return this->storage_->latest()->hash();
}

bool CometBlockchain::initialized() {
  return this->options_ != nullptr;
}

void CometBlockchain::initializeBlockchain() {
  this->options_ = std::make_unique<Options>(Options::fromFile(blockchainPath_));
  this->db_ = std::make_unique<DB>(blockchainPath_ + "/database");
  this->storage_ = std::make_unique<Storage>(this->db_, this->options_);
  this->state_ = std::make_unique<State>(this->db_, this->storage_, this->options_);
  this->httpServer_ = std::make_unique<HTTPServer>(this->state_, this->storage_, this->options_);
  this->httpServer_->start();
}

void CometBlockchain::checkTx(const tendermint::abci::RequestCheckTx* request, tendermint::abci::ResponseCheckTx* response) {
  try {
    std::cout << "Checking Transaction Bytes: " << request->tx() << std::endl;
    Bytes txBytes(Hex::toBytes(request->tx()));
    TxBlock transaction(txBytes, this->options_->getChainID());
    auto txHash = transaction.hash();
    auto txInvalid = this->state_->addTx(std::move(transaction));
    if (txInvalid) {
      if (txInvalid == TxInvalid::InvalidBalance) {
        response->set_code(1);
        response->set_log("Tx Invalid Balance");
        response->set_info("Tx Failed!");
      } else if (txInvalid == TxInvalid::InvalidNonce) {
        response->set_code(1);
        response->set_log("Tx Invalid Nonce");
        response->set_info("Tx Failed!");
      }
      return;
    }
    response->set_code(0);
    response->set_data(txHash.hex());
    response->set_gas_used(21000);
    response->set_gas_wanted(21000);
  } catch (std::exception &e) {
    response->set_code(1);
    response->set_log(e.what());
    response->set_info("Tx Failed!");
  }
}

void CometBlockchain::prepareProposal(const tendermint::abci::RequestPrepareProposal* request, tendermint::abci::ResponsePrepareProposal* response) {
  uint64_t maxBytes = request->max_tx_bytes() - 300; /// Block overhead
  uint64_t totalBytes = 0;
  uint64_t nHeight = request->height();
  std::cout << "Preparing Proposal for block height: " << nHeight << " timestamp " << google::protobuf::util::TimeUtil::ToString(request->time()) << std::endl;

  auto mempool = this->state_->getMempool();
  for (auto const& [hash, tx] : mempool) {
    auto txBytes = tx.rlpSerialize(true);
    totalBytes += txBytes.size();
    if (totalBytes > maxBytes) {
      break;
    }
    std::cout << "Adding Tx: " << tx.hash().hex() << " To Proposal from mempool" << std::endl;
    response->add_txs(Hex::fromBytes(txBytes));
  }

  for (auto const& txBytes : request->txs()) {
    totalBytes += txBytes.size();
    TxBlock transaction(Hex::toBytes(txBytes), this->options_->getChainID());
    if (mempool.contains(transaction.hash())) {
      continue;
    }
    if (totalBytes > maxBytes) {
      break;
    }
    std::cout << "Adding Tx: " << transaction.hash().hex() << " To Proposal" << std::endl;
    response->add_txs(txBytes);
  }

}

void CometBlockchain::finalizeBlock(const tendermint::abci::RequestFinalizeBlock* request, tendermint::abci::ResponseFinalizeBlock* response) {
  uint64_t timestamp = TimestampToMicroseconds(request->time());
  uint64_t nHeight = request->height();
  PrivKey validatorPrivKey = Utils::sha3(Utils::stringToBytes("OrbiterSDK is the best"));
  std::cout << "Finalizing Block for block height: " << nHeight << " timestamp " << google::protobuf::util::TimeUtil::ToString(request->time()) << std::endl;
  std::cout << "Block has " << request->txs().size() << " transactions" << std::endl;
  auto prevBlockHash = this->storage_->latest()->hash();
  this->newBestBlock_ = std::make_unique<Block>(prevBlockHash, timestamp, nHeight);
  for (const auto& txBytes : request->txs()) {
    TxBlock transaction(Hex::toBytes(txBytes), this->options_->getChainID());
    auto result = response->add_tx_results();
    result->set_code(0);
    result->set_data(transaction.hash().hex());
    result->set_gas_used(21000);
    result->set_gas_wanted(21000);
    this->newBestBlock_->appendTx(transaction);
  }
  this->newBestBlock_->finalize(validatorPrivKey);
  response->set_app_hash(this->newBestBlock_->hash().hex());
}
void CometBlockchain::commit() {
  std::cout << "Committing Block: " << this->newBestBlock_->hash().hex() << " with " << this->newBestBlock_->getTxs().size() << " transactions" << std::endl;
  this->state_->processNextBlock(std::move(*this->newBestBlock_));
}