#pragma once

#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
#else
using SocketHandle = int;
#endif

#include "dcon/types.h"

bool InitSockets();
void ShutdownSockets();
void CloseSocket(SocketHandle socket);

bool ReadExact(SocketHandle fd, unsigned char* buf, size_t len);
bool WriteExact(SocketHandle fd, const unsigned char* buf, size_t len);
bool SendMessage(SocketHandle fd, const std::string& type, const Bytes& payload);
bool ReceiveMessage(SocketHandle fd, std::string& type, Bytes& payload);

SocketHandle ConnectToPeer(const std::string& address);
SocketHandle CreateServerSocket(int port);

std::vector<std::string> SplitList(const std::string& list);
std::vector<std::string> ResolveSeedPeers(const std::string& seed,
                                          int defaultPort,
                                          size_t maxResults);
void BroadcastToPeers(const std::vector<std::string>& peers,
                      const std::string& type,
                      const Bytes& payload);
