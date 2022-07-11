#include "kissnet.hpp"

template
class KISSNET_API kissnet::socket<kissnet::protocol::tcp>;

#ifdef KISSNET_USE_OPENSSL
template
class KISSNET_API kissnet::socket<kissnet::protocol::tcp_ssl>;
#endif //KISSNET_USE_OPENSSL

template
class KISSNET_API kissnet::socket<kissnet::protocol::udp>;

template<>
std::map<SOCKET, kissnet::tcp_socket*> KISSNET_API kissnet::tcp_socket::sockets {};

#ifdef KISSNET_USE_OPENSSL
template<>
std::map<SOCKET, kissnet::tcp_ssl_socket*> KISSNET_API kissnet::tcp_ssl_socket::sockets {};
#endif //KISSNET_USE_OPENSSL

template<>
std::map<SOCKET, kissnet::udp_socket*> KISSNET_API kissnet::udp_socket::sockets {};

