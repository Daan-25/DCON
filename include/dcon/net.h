#pragma once

#include <string>
#include <vector>

#include "dcon/types.h"

bool ReadExact(int fd, unsigned char* buf, size_t len);
bool WriteExact(int fd, const unsigned char* buf, size_t len);
bool SendMessage(int fd, const std::string& type, const Bytes& payload);
bool ReceiveMessage(int fd, std::string& type, Bytes& payload);

int ConnectToPeer(const std::string& address);
int CreateServerSocket(int port);

std::vector<std::string> SplitList(const std::string& list);
void BroadcastToPeers(const std::vector<std::string>& peers,
                      const std::string& type,
                      const Bytes& payload);
