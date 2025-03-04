/*
Copyright (c) [2023-2024] [Sparq Network]

This software is distributed under the MIT License.
See the LICENSE.txt file in the project root for more information.
*/

#include "managerbase.h"

namespace P2P {

  bool ManagerBase::registerSessionInternal(const std::shared_ptr<Session>& session) {
    std::unique_lock lockSession(this->sessionsMutex_); // ManagerBase::registerSessionInternal can change sessions_ map.
    if (!this->started_) {
      return false;
    }
    // The NodeID of a session is made by the host IP and his server port.
    // That means, it is possible for us to receive a inbound connection for someone that we already have a outbound connection.
    // In this case, we will keep the oldest connection alive and close the new one.
    // The other endpoint will also see that we already have a connection and will close the new one.
    if (sessions_.contains(session->hostNodeId())) {
      lockSession.unlock(); // Unlock before calling logToDebug to avoid waiting for the lock in the logToDebug function.
      Logger::logToDebug(LogType::ERROR, Log::P2PManager, __func__, "Session already exists at " +
                        session->hostNodeId().first.to_string() + ":" + std::to_string(session->hostNodeId().second));
      return false;
    }
    Logger::logToDebug(LogType::INFO, Log::P2PManager, __func__, "Registering session at " +
                      session->hostNodeId().first.to_string() + ":" + std::to_string(session->hostNodeId().second));
    sessions_.insert({session->hostNodeId(), session});
    return true;
  }

  bool ManagerBase::unregisterSessionInternal(const std::shared_ptr<Session> &session) {
    std::unique_lock lockSession(this->sessionsMutex_); // ManagerBase::unregisterSessionInternal can change sessions_ map.
    if (!this->started_) {
      return false;
    }
    if (!sessions_.contains(session->hostNodeId())) {
      lockSession.unlock(); // Unlock before calling logToDebug to avoid waiting for the lock in the logToDebug function.
      Logger::logToDebug(LogType::ERROR, Log::P2PManager, __func__, "Session does not exist at " +
                        session->hostNodeId().first.to_string() + ":" + std::to_string(session->hostNodeId().second));
      return false;
    }
    sessions_.erase(session->hostNodeId());
    return true;
  }

  bool ManagerBase::disconnectSessionInternal(const NodeID& nodeId) {
    std::unique_lock lockSession(this->sessionsMutex_); // ManagerBase::disconnectSessionInternal can change sessions_ map.
    if (!this->started_) {
      return false;
    }
    if (!sessions_.contains(nodeId)) {
      lockSession.unlock(); // Unlock before calling logToDebug to avoid waiting for the lock in the logToDebug function.
      Logger::logToDebug(LogType::ERROR, Log::P2PManager, __func__, "Session does not exist at " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
      return false;
    }
    Logger::logToDebug(LogType::INFO, Log::P2PManager, __func__, "Disconnecting session at " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
    // Get a copy of the pointer
    sessions_[nodeId]->close();
    sessions_.erase(nodeId);
    return true;
  }

  std::shared_ptr<Request> ManagerBase::sendRequestTo(const NodeID &nodeId, const std::shared_ptr<const Message>& message) {
    if (!this->started_) return nullptr;
    std::shared_lock<std::shared_mutex> lockSession(this->sessionsMutex_); // ManagerBase::sendRequestTo doesn't change sessions_ map.
    if(!sessions_.contains(nodeId)) {
      lockSession.unlock(); // Unlock before calling logToDebug to avoid waiting for the lock in the logToDebug function.
      Logger::logToDebug(LogType::ERROR, Log::P2PManager, __func__, "Session does not exist at " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
      return nullptr;
    }
    auto session = sessions_[nodeId];
    // We can only request ping, info and requestNode to discovery nodes
    if (session->hostType() == NodeType::DISCOVERY_NODE &&
      (message->command() == CommandType::Info || message->command() == CommandType::RequestValidatorTxs)
    ) {
      lockSession.unlock(); // Unlock before calling logToDebug to avoid waiting for the lock in the logToDebug function.
      Logger::logToDebug(LogType::INFO, Log::P2PManager, __func__, "Session is discovery, cannot send message");
      return nullptr;
    }
    std::unique_lock lockRequests(this->requestsMutex_);
    requests_[message->id()] = std::make_shared<Request>(message->command(), message->id(), session->hostNodeId(), message);
    session->write(message);
    return requests_[message->id()];
  }

  // ManagerBase::answerSession doesn't change sessions_ map, but we still need to
  // be sure that the session io_context doesn't get deleted while we are using it.
  void ManagerBase::answerSession(const NodeID &nodeId, const std::shared_ptr<const Message>& message) {
    std::shared_lock lockSession(this->sessionsMutex_);
    if (!this->started_) return;
    auto it = sessions_.find(nodeId);
    if (it == sessions_.end()) {
      Logger::logToDebug(LogType::ERROR, Log::P2PManager, __func__, "Cannot find session for " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
      return;
    }
    it->second->write(message);
  }

  void ManagerBase::start() {
    std::scoped_lock lock(this->stateMutex_);
    if (this->started_) return;
    this->started_ = true;
    this->threadPool_ = std::make_unique<BS::thread_pool_light>(4);
    this->server_.start();
    this->clientfactory_.start();
  }

  void ManagerBase::stop() {
    std::scoped_lock lock(this->stateMutex_);
    if (! this->started_) return;
    this->started_ = false;
    {
      std::unique_lock lock(this->sessionsMutex_);
      for (auto it = sessions_.begin(); it != sessions_.end();) {
        std::weak_ptr<Session> session = std::weak_ptr(it->second);
        it = sessions_.erase(it);
        if (auto sessionPtr = session.lock()) sessionPtr->close();
      }
    }
    this->server_.stop();
    this->clientfactory_.stop();
    this->threadPool_.reset();
  }

  void ManagerBase::asyncHandleMessage(const NodeID &nodeId, const std::shared_ptr<const Message> message) {
    std::shared_lock lock(this->stateMutex_);
    if (this->threadPool_) {
      this->threadPool_->push_task(&ManagerBase::handleMessage, this, nodeId, message);
    }
  }

  std::vector<NodeID> ManagerBase::getSessionsIDs() const {
    std::vector<NodeID> nodes;
    std::shared_lock<std::shared_mutex> lock(this->sessionsMutex_);
    for (auto& [nodeId, session] : this->sessions_) nodes.push_back(nodeId);
    return nodes;
  }

  std::vector<NodeID> ManagerBase::getSessionsIDs(const NodeType& type) const {
    std::vector<NodeID> nodes;
    std::shared_lock<std::shared_mutex> lock(this->sessionsMutex_);
    for (auto& [nodeId, session] : this->sessions_) if (session->hostType() == type) nodes.push_back(nodeId);
    return nodes;
  }

  bool ManagerBase::registerSession(const std::shared_ptr<Session> &session) {
    return this->registerSessionInternal(session);
  }

  bool ManagerBase::unregisterSession(const std::shared_ptr<Session> &session) {
    return this->unregisterSessionInternal(session);
  }

  bool ManagerBase::disconnectSession(const NodeID& nodeId) {
    return this->disconnectSessionInternal(nodeId);
  }

  void ManagerBase::connectToServer(const boost::asio::ip::address& address, uint16_t port) {
    if (!this->started_) return;
    if (address == this->server_.getLocalAddress() && port == this->serverPort_) return; /// Cannot connect to itself.
    {
      std::shared_lock<std::shared_mutex> lock(this->sessionsMutex_);
      if (this->sessions_.contains({address, port})) return; // Node is already connected
    }
    this->clientfactory_.connectToServer(address, port);
  }

  void ManagerBase::ping(const NodeID& nodeId) {
    auto request = std::make_shared<const Message>(RequestEncoder::ping());
    Utils::logToFile("Pinging " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
    auto requestPtr = sendRequestTo(nodeId, request);
    if (requestPtr == nullptr) throw DynamicException(
      "Failed to send ping to " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second)
    );
    requestPtr->answerFuture().wait();
  }

  // TODO: Both ping and requestNodes is a blocking call on .wait()
  // Somehow change to wait_for.
  std::unordered_map<NodeID, NodeType, SafeHash> ManagerBase::requestNodes(const NodeID& nodeId) {
    auto request = std::make_shared<const Message>(RequestEncoder::requestNodes());
    Utils::logToFile("Requesting nodes from " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second));
    auto requestPtr = sendRequestTo(nodeId, request);
    if (requestPtr == nullptr) {
      Logger::logToDebug(LogType::ERROR, Log::P2PParser, __func__, "Request to " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second) + " failed.");
      return {};
    }
    auto answer = requestPtr->answerFuture();
    auto status = answer.wait_for(std::chrono::seconds(2));
    if (status == std::future_status::timeout) {
      Logger::logToDebug(LogType::ERROR, Log::P2PParser, __func__, "Request to " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second) + " timed out.");
      return {};
    }
    try {
      auto answerPtr = answer.get();
      return AnswerDecoder::requestNodes(*answerPtr);
    } catch (std::exception &e) {
      Logger::logToDebug(LogType::ERROR, Log::P2PParser, __func__,
        "Request to " + nodeId.first.to_string() + ":" + std::to_string(nodeId.second) + " failed with error: " + e.what()
      );
      return {};
    }
  }
}
