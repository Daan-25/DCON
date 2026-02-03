#include "dcon/net.h"

#ifdef _WIN32
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <cstring>

#include "dcon/serialize.h"

bool InitSockets() {
#ifdef _WIN32
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
  return true;
#endif
}

void ShutdownSockets() {
#ifdef _WIN32
  WSACleanup();
#endif
}

void CloseSocket(SocketHandle socket) {
#ifdef _WIN32
  closesocket(socket);
#else
  close(socket);
#endif
}

static bool IsValidSocket(SocketHandle socket) {
#ifdef _WIN32
  return socket != INVALID_SOCKET;
#else
  return socket >= 0;
#endif
}

bool ReadExact(SocketHandle fd, unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    auto n = recv(fd, reinterpret_cast<char*>(buf + total),
                  static_cast<int>(len - total), 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

bool WriteExact(SocketHandle fd, const unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    auto n = send(fd, reinterpret_cast<const char*>(buf + total),
                  static_cast<int>(len - total), 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

static bool ReadU32FromSocket(SocketHandle fd, uint32_t& out) {
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

static bool ReadBytesFromSocket(SocketHandle fd, Bytes& out, uint32_t len) {
  out.resize(len);
  if (len == 0) {
    return true;
  }
  return ReadExact(fd, out.data(), len);
}

bool SendMessage(SocketHandle fd, const std::string& type, const Bytes& payload) {
  ByteWriter w;
  w.WriteString(type);
  w.WriteBytes(payload);
  return WriteExact(fd, w.data.data(), w.data.size());
}

bool ReceiveMessage(SocketHandle fd, std::string& type, Bytes& payload) {
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

SocketHandle ConnectToPeer(const std::string& address) {
  std::string host;
  int port = 0;
  if (!SplitHostPort(address, host, port)) {
    return static_cast<SocketHandle>(-1);
  }

  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* res = nullptr;
  std::string portStr = std::to_string(port);
  if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
    return static_cast<SocketHandle>(-1);
  }

  SocketHandle sock = static_cast<SocketHandle>(-1);
  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (!IsValidSocket(sock)) {
      continue;
    }
    if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
      break;
    }
    CloseSocket(sock);
    sock = static_cast<SocketHandle>(-1);
  }

  freeaddrinfo(res);
  return sock;
}

SocketHandle CreateServerSocket(int port) {
  SocketHandle sock = socket(AF_INET, SOCK_STREAM, 0);
  if (!IsValidSocket(sock)) {
    return static_cast<SocketHandle>(-1);
  }
  int yes = 1;
#ifdef _WIN32
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    CloseSocket(sock);
    return static_cast<SocketHandle>(-1);
  }
  if (listen(sock, 16) < 0) {
    CloseSocket(sock);
    return static_cast<SocketHandle>(-1);
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
    SocketHandle sock = ConnectToPeer(peer);
    if (!IsValidSocket(sock)) {
      continue;
    }
    SendMessage(sock, type, payload);
    CloseSocket(sock);
  }
}
