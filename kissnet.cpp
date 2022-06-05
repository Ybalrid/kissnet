#include "kissnet.hpp"

template<>
std::map<SOCKET, kissnet::tcp_socket*> kissnet::tcp_socket::sockets {};

#ifdef KISSNET_USE_OPENSSL
template<>
std::map<SOCKET, kissnet::tcp_ssl_socket*> kissnet::tcp_ssl_socket::sockets {};
#endif //KISSNET_USE_OPENSSL

template<>
std::map<SOCKET, kissnet::udp_socket*> kissnet::udp_socket::sockets {};

