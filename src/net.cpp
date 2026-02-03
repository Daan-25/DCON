#include "dcon/net.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "dcon/serialize.h"

bool ReadExact(int fd, unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, buf + total, len - total, 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

bool WriteExact(int fd, const unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = send(fd, buf + total, len - total, 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

static bool ReadU32FromSocket(int fd, uint32_t& out) {
  unsigned char buf[4];
  if (!ReadExact(fd, buf, sizeof(buf))) {
    return false;
  }
  out = static_cast<uint32_t>(buf[0]) |
        (static_cast<uint32_t>(buf[1]) << 8) |
        (static_cast<uint32_t>(buf[2]) << 16) |
        (static_cast<uint32_t>(buf[3]) << 24);
  return true;
}

static bool ReadBytesFromSocket(int fd, Bytes& out, uint32_t len) {
  out.resize(len);
  if (len == 0) {
    return true;
  }
  return ReadExact(fd, out.data(), len);
}

bool SendMessage(int fd, const std::string& type, const Bytes& payload) {
  ByteWriter w;
  w.WriteString(type);
  w.WriteBytes(payload);
  return WriteExact(fd, w.data.data(), w.data.size());
}

bool ReceiveMessage(int fd, std::string& type, Bytes& payload) {
  uint32_t typeLen = 0;
  if (!ReadU32FromSocket(fd, typeLen)) {
    return false;
  }
  if (typeLen > 1024) {
    return false;
  }
  Bytes typeBytes;
  if (!ReadBytesFromSocket(fd, typeBytes, typeLen)) {
    return false;
  }
  type.assign(typeBytes.begin(), typeBytes.end());

  uint32_t payloadLen = 0;
  if (!ReadU32FromSocket(fd, payloadLen)) {
    return false;
  }
  if (payloadLen > (128u << 20)) {
    return false;
  }
  return ReadBytesFromSocket(fd, payload, payloadLen);
}

static bool SplitHostPort(const std::string& input, std::string& host, int& port) {
  size_t pos = input.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  host = input.substr(0, pos);
  if (host.empty()) {
    host = "127.0.0.1";
  }
  try {
    port = std::stoi(input.substr(pos + 1));
  } catch (...) {
    return false;
  }
  return port > 0;
}

int ConnectToPeer(const std::string& address) {
  std::string host;
  int port = 0;
  if (!SplitHostPort(address, host, port)) {
    return -1;
  }

  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* res = nullptr;
  std::string portStr = std::to_string(port);
  if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
    return -1;
  }

  int sock = -1;
  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock < 0) {
      continue;
    }
    if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
      break;
    }
    close(sock);
    sock = -1;
  }

  freeaddrinfo(res);
  return sock;
}

int CreateServerSocket(int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return -1;
  }
  int yes = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(sock);
    return -1;
  }
  if (listen(sock, 16) < 0) {
    close(sock);
    return -1;
  }
  return sock;
}

std::vector<std::string> SplitList(const std::string& list) {
  std::vector<std::string> out;
  std::string current;
  for (char c : list) {
    if (c == ',') {
      if (!current.empty()) {
        out.push_back(current);
      }
      current.clear();
    } else if (c != ' ') {
      current.push_back(c);
    }
  }
  if (!current.empty()) {
    out.push_back(current);
  }
  return out;
}

void BroadcastToPeers(const std::vector<std::string>& peers,
                      const std::string& type,
                      const Bytes& payload) {
  for (const auto& peer : peers) {
    int sock = ConnectToPeer(peer);
    if (sock < 0) {
      continue;
    }
    SendMessage(sock, type, payload);
    close(sock);
  }
}
