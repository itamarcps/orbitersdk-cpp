if(BUILD_AVALANCHEGO)
  set(NET_HEADERS
    ${CMAKE_SOURCE_DIR}/src/net/http/httpclient.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpparser.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpsession.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httplistener.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpserver.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/methods.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/encoding.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/decoding.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/encoding.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/session.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/client.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/server.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerbase.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerdiscovery.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managernormal.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/discovery.h
    PARENT_SCOPE
  )

  set(NET_SOURCES
    ${CMAKE_SOURCE_DIR}/src/net/http/httpparser.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpclient.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpsession.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httplistener.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpserver.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/encoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/decoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/encoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/session.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/client.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/server.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerbase.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerdiscovery.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managernormal.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/discovery.cpp
    PARENT_SCOPE
  )
else()
  set(NET_HEADERS
    ${CMAKE_SOURCE_DIR}/src/net/http/httpparser.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpsession.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httplistener.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpclient.h
    ${CMAKE_SOURCE_DIR}/src/net/http/httpserver.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/methods.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/encoding.h
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/decoding.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/encoding.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/session.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/client.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/server.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerbase.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerdiscovery.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managernormal.h
    ${CMAKE_SOURCE_DIR}/src/net/p2p/discovery.h
    PARENT_SCOPE
  )

  set(NET_SOURCES
    ${CMAKE_SOURCE_DIR}/src/net/http/httpparser.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpsession.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httplistener.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpclient.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/httpserver.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/encoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/http/jsonrpc/decoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/encoding.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/session.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/client.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/server.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerbase.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managerdiscovery.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/managernormal.cpp
    ${CMAKE_SOURCE_DIR}/src/net/p2p/discovery.cpp
    PARENT_SCOPE
  )
endif()

