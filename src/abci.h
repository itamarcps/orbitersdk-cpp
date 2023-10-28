#ifndef ABCI_H
#define ABCI_H

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <grpc/support/log.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>

#include <google/protobuf/message.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/time_util.h>

#include "../proto/abci-types.grpc.pb.h"

#include "core/storage.h"
#include "core/state.h"
#include "net/http/httpserver.h"


using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::Status;

uint64_t TimestampToMicroseconds(const google::protobuf::Timestamp& timestamp);
google::protobuf::Timestamp MicrosecondsToTimestamp(uint64_t microseconds);

/// Forward Declaration
class CometBlockchain;
class ABCIServiceImplementation  final : public tendermint::abci::ABCI::Service, public std::enable_shared_from_this<ABCIServiceImplementation> {
  private:
    CometBlockchain& blockchain_;
  public:
    explicit ABCIServiceImplementation(CometBlockchain& blockchain) : blockchain_(blockchain) {}

    Status Echo(ServerContext* context, const tendermint::abci::RequestEcho* request, tendermint::abci::ResponseEcho* response) override;

    Status Flush(ServerContext* context, const tendermint::abci::RequestFlush* request, tendermint::abci::ResponseFlush* response) override;

    Status Info(ServerContext* context, const tendermint::abci::RequestInfo* request, tendermint::abci::ResponseInfo* response) override;

    Status CheckTx(ServerContext* context, const tendermint::abci::RequestCheckTx* request, tendermint::abci::ResponseCheckTx* response) override;

    Status Query(ServerContext* context, const tendermint::abci::RequestQuery* request, tendermint::abci::ResponseQuery* response) override;

    Status Commit(ServerContext* context, const tendermint::abci::RequestCommit* request, tendermint::abci::ResponseCommit* response) override;

    Status InitChain(ServerContext* context, const tendermint::abci::RequestInitChain* request, tendermint::abci::ResponseInitChain* response) override;

    Status ListSnapshots(ServerContext* context, const tendermint::abci::RequestListSnapshots* request, tendermint::abci::ResponseListSnapshots* response) override;

    Status OfferSnapshot(ServerContext* context, const tendermint::abci::RequestOfferSnapshot* request, tendermint::abci::ResponseOfferSnapshot* response) override;

    Status LoadSnapshotChunk(ServerContext* context, const tendermint::abci::RequestLoadSnapshotChunk* request, tendermint::abci::ResponseLoadSnapshotChunk* response) override;

    Status ApplySnapshotChunk(ServerContext* context, const tendermint::abci::RequestApplySnapshotChunk* request, tendermint::abci::ResponseApplySnapshotChunk* response) override;

    Status PrepareProposal(ServerContext* context, const tendermint::abci::RequestPrepareProposal* request, tendermint::abci::ResponsePrepareProposal* response) override;

    Status ProcessProposal(ServerContext* context, const tendermint::abci::RequestProcessProposal* request, tendermint::abci::ResponseProcessProposal* response) override;

    Status ExtendVote(ServerContext* context, const tendermint::abci::RequestExtendVote* request, tendermint::abci::ResponseExtendVote* response) override;

    Status VerifyVoteExtension(ServerContext* context, const tendermint::abci::RequestVerifyVoteExtension* request, tendermint::abci::ResponseVerifyVoteExtension* response)override;

    Status FinalizeBlock(ServerContext* context, const tendermint::abci::RequestFinalizeBlock* request, tendermint::abci::ResponseFinalizeBlock* response) override;
};

class CometBlockchain {
  private:
    std::shared_ptr<ABCIServiceImplementation> abci_;
    std::shared_ptr<Server> grpcServer;
    std::unique_ptr<Options> options_;
    std::unique_ptr<DB> db_;
    std::unique_ptr<Storage> storage_;
    std::unique_ptr<State> state_;
    std::unique_ptr<HTTPServer> httpServer_;
    /// newBestBlock_ is created by FinalizeBlock
    /// and commited to State with CommitBlock
    std::unique_ptr<Block> newBestBlock_;
    std::string blockchainPath_;
  public:
    CometBlockchain();

    void startChain();
    uint64_t getBestBlockHeight() const;
    Hash getBestBlockHash() const;
    bool initialized();
    void initializeBlockchain();
    void checkTx(const tendermint::abci::RequestCheckTx* request, tendermint::abci::ResponseCheckTx* response);
    void prepareProposal(const tendermint::abci::RequestPrepareProposal* request, tendermint::abci::ResponsePrepareProposal* response);
    void finalizeBlock(const tendermint::abci::RequestFinalizeBlock* request, tendermint::abci::ResponseFinalizeBlock* response);
    void commit();
};

#endif