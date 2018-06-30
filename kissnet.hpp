/*
 * MIT License
 *
 * Copyright (c) 2018 Arthur Brainville
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * INTRODUCTION
 * ============
 *
 * Kissnet is a simple C++17 layer around the raw OS provided socket API to be used on
 * IP networks with the TCP and UDP protocols.
 *
 * Kissnet is not a networking framework, and it will not process your data or assist you
 * in any way. Kissnet's only goal is to provide a simple API to send and receive bytes,
 * without having to play around with a bunch of structure, file descriptors, handles and
 * pointers given to a C-style API. The other goal of kissnet is to provide an API that will
 * works in a cross platform setting.
 *
 * Kissnet will automatically manage the eventual startup/shutdown of the library needed to
 * perform socket operations on a particular platform. (e.g. the Windows Socket API on
 * MS-Windows.
 *
 * Kissnet leverages (and expect you to do so), multiple features from C++17, including: std::byte,
 * if constexpr, structured bindings, if-initializer and template parameter type deduction.
 *
 * The library is structured accross 4 exposed data types:
 *
 *  - buffer<size_t> : a static array of std::byte implemented via std::array. This is what you should
 *  use to hold raw data you are getting from a socket, before extracting what you need from the bytes
 *  - port_t : a 16 bit unsiged number. Represent a network port number
 *  - endpoint : a structure that represent a location where you need to connect to. Contains a hostname
 *  (as std::string) and a port number (as port_t)
 *  - socket<protocol, ip> : a templated class that represent a socket. Protocol is either tcp or udp,
 *  and ip is either v4 or v6
 *
 * Kissnet does error handling in 2 ways:
 *
 *  1:
 *  When an operation can generate an error that the user should handle by hand anyway, a tuple
 *  containing the expected type returned, and an object that represent the status of what happend
 *  is returned.
 *
 *  For example, socket send/receive operation can discover that the connexion was closed, or was shutted down properly.
 *  It could also be the fact that a socket was configured "non blocking" and would have blocked in this situation.
 *  On both occasion, these methods will return the fact that 0 bytes came accross as the transaction size, and the status will
 *  indicate either an error (socket no longer valid), or an actual status message (connexion closed, socket would
 *  have blocked)
 *
 *  These status objects will behave like a const bool that equals "false" when an error occured, and "true" when it's just a
 *  status notification
 *
 *  2:
 *  Fatal errors are by default handled by throwing a runtime_error exception. But, for many reasons, you may want to
 *  not use exceptions entirely.
 *
 *  kissnet give you some facilities to get fatal errors informations back, and to choose how to handle it. Kissnet give
 *  you a few levers you can use:
 *
 *  - You can deactivate the exception support by #defining KISSNET_NO_EXCEP before #including kissnet.hpp. Insteand, kissnet will use a function based error handler
 *  - By default, the error handler prints to stderr the error message, and abort the program
 *  - kissnet::error::callback is a function pointer that gets a string, and a context pointer. The string is the error message, and the context pointer
 * what ever you gived kissnet for the occasion. This is a global pointer that you can set as you want. This will override the "print to stderr" behavior at fatal error time.
 *  - kissnet::error::ctx is a void*, this will be passed to your error handler as a "context" pointer. If you need your handler to write to a log, or to turn on the HTCPCP enabled teapot on John's desk, you can.
 *  - kissnet::abortOnFatalError is a boolean that will control the call to abort(). This is independent to the fact that you did set or not an error callback.
 * please note that any object involved with the operation that triggered the fatal error is probably in an invalid state, and probably deserve to be thrown away.
 *
 *
 */

#ifndef KISS_NET
#define KISS_NET

#ifndef KISSNET_NO_EXCEP
#define kissnet_fatal_error(STR) throw std::runtime_error(STR)
#else
#define kissnet_fatal_error(STR) kissnet::error::handle(STR);
#endif

#include <array>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <stdexcept>
#include <string>

#ifdef _WIN32

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

using ioctl_setting = u_long;
using buffsize_t	= int;

//Handle WinSock2/Windows Socket API initialziation and cleanup
#pragma comment(lib, "Ws2_32.lib")
namespace kissnet
{

	namespace win32_specifc
	{
	///Forward declare the object that will permit to manage the WSAStartup/Cleanup automatically
	struct WSA;

	///Enclose the global pointer in this namespace. Only use this inside a shared_ptr
	namespace internal_state
	{
		static WSA* global_WSA = nullptr;
	}

	///WSA object
	struct WSA : std::enable_shared_from_this<WSA>
	{
		///data storage
		WSADATA wsa_data;

		///Stratup
		WSA()
		{
			WSAStartup(MAKEWORD(2, 2), &wsa_data);
		}

		///Cleanup
		~WSA()
		{
			WSACleanup();
			internal_state::global_WSA = nullptr;
		}

		///get the shared pointer
		std::shared_ptr<WSA> getPtr()
		{
			return shared_from_this();
		}
	};

	///Get-or-create the global pointer
	std::shared_ptr<WSA> getWSA()
	{
		//If it has been created already:
		if(internal_state::global_WSA)
			return internal_state::global_WSA->getPtr(); //fetch the smart pointer from the naked pointer

		//Create in wsa
		auto wsa = std::make_shared<WSA>();

		//Save the raw address in the global state
		internal_state::global_WSA = wsa.get();

		//Return the smart pointer
		return wsa;
	}

	}

#define KISSNET_OS_SPECIFIC_PAYLOAD_NAME wsa_ptr
#define KISSNET_OS_SPECIFIC std::shared_ptr<kissnet::win32_specific::WSA> KISSNET_OS_SPECIFIC_PAYLOAD_NAME
#define KISSNET_OS_INIT KISSNET_OS_SPECIFIC_PAYLOAD_NAME = kissnet::win32_specific::getWSA()

	///Return the last error code
	int get_error_code()
	{
		const auto error = WSAGetLastError();

		//We need to posixify the values that we are actually using inside this header.
		switch(error)
		{
			case WSAEWOULDBLOCK:
				return EWOULDBLOCK;
			default:
				return error;
		}
	}
}
#else //UNIX platform

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

using ioctl_setting = int;
using buffsize_t	= size_t;

//To get consistant socket API between Windows and Linux:
static const int INVALID_SOCKET = -1;
static const int SOCKET_ERROR   = -1;
using SOCKET					= int;
using SOCKADDR_IN				= sockaddr_in;
using SOCKADDR					= sockaddr;
using IN_ADDR					= in_addr;

//Wrap them in their WIN32 names
int closesocket(SOCKET in)
{
	return close(in);
}

template <typename... Params>
int ioctlsocket(int fd, int request, Params&&... params)
{
	return ioctl(fd, request, params...);
}

#define KISSNET_OS_SPECIFIC_PAYLOAD_NAME dummy
#define KISSNET_OS_SPECIFIC char dummy
#define KISSNET_OS_INIT dummy = 42;

namespace unix_specific
{

}

int get_error_code()
{
	return errno;
}

#endif

///Main namespace of kissnet
namespace kissnet
{

	///Exception-less error handling infrastructure
	namespace error
	{
		static void (*callback)(const std::string&, void* ctx) = nullptr;
		static void* ctx									   = nullptr;
		static bool abortOnFatalError						   = true;

		void handler(const std::string& str)
		{
			//if the error::callback function has been provided, call that
			if(callback)
			{
				callback(str, ctx);
			}
			//Print error into the standard error output
			else
			{
				fputs(str.c_str(), stderr);
			}

			//If the error abort hasn't been deactivated
			if(abortOnFatalError)
			{
				abort();
			}
		}
	}

	///low level protocol used, between TCP and UDP
	enum class protocol { tcp,
						  udp };

	///Represent ipv4 vs ipv6
	enum class ip {
		v4,
		v6
	};

	///buffer is an array of std::byte
	template <size_t buff_size>
	using buffer = std::array<std::byte, buff_size>;

	///port_t is the port
	using port_t = uint16_t;

	///An endpoint is where the network will connect to (address and port)
	struct endpoint
	{
		///The address to connect to
		std::string address{};

		///The port to connect to
		port_t port{};

		///Default constructor, the endpoitn is not valid at that point, but you can set the address/port manually
		endpoint() = default;

		///Basically create the endpoint with what you give it
		endpoint(std::string addr, port_t prt) :
		 address{ addr }, port{ prt }
		{}

		///Construct the endpoint from "address:port"
		endpoint(std::string addr)
		{
			const auto separator = addr.find_last_of(':');
			if(separator == std::string::npos)
			{
				//error here
			}

			if(separator == addr.size() - 1)
			{
				//error here
			}

			address = addr.substr(0, separator);
			port	= (port_t)strtoul(addr.substr(separator + 1).c_str(), nullptr, 10);
		}

		///Construct an endpoint from a SOCKADDR
		endpoint(SOCKADDR* addr)
		{
			switch(addr->sa_family)
			{
				case AF_INET:
				{
					auto ip_addr = (SOCKADDR_IN*)(addr);
					address		 = inet_ntoa(ip_addr->sin_addr);
					port		 = ip_addr->sin_port;
				}
				break;

				case AF_INET6:
				{
					auto ip_addr = (sockaddr_in6*)(addr);
					char buffer[INET6_ADDRSTRLEN];
					address = inet_ntop(AF_INET6, &(ip_addr->sin6_addr), buffer, INET6_ADDRSTRLEN);
					port	= ip_addr->sin6_port;
				}
				break;
			}

			if(address.empty())
			{
				kissnet_fatal_error("Couldn't construct endpoint from sockaddr(_storage) struct");
			}
		}
	};

	//Wrap "system calls" here to avoid conflicts with the names used in the socket class

	///socket()
	auto syscall_socket = [](int af, int type, int protocol) {
		return ::socket(af, type, protocol);
	};

	///recv()
	auto syscall_recv = [](SOCKET s, char* buff, buffsize_t len, int flags) {
		return ::recv(s, buff, len, flags);
	};

	///send()
	auto syscall_send = [](SOCKET s, const char* buff, buffsize_t len, int flags) {
		return ::send(s, buff, len, flags);
	};

	///bind()
	auto syscall_bind = [](SOCKET s, const struct sockaddr* name, socklen_t namelen) {
		return ::bind(s, name, namelen);
	};

	///connect()
	auto syscall_connect = [](SOCKET s, const struct sockaddr* name, socklen_t namelen) {
		return ::connect(s, name, namelen);
	};

	///listen()
	auto syscall_listen = [](SOCKET s, int backlog) {
		return ::listen(s, backlog);
	};

	///accept()
	auto syscall_accept = [](SOCKET s, struct sockaddr* addr, socklen_t* addrlen) {
		return ::accept(s, addr, addrlen);
	};

	///Represent the status of a socket as returned by a socket operation (send, received). Implictly convertible to bool
	struct socket_status
	{
		///Enumeration of socket status, with a 1 byte footprint
		enum values : uint8_t {
			errored							= 0x0,
			valid							= 0x1,
			cleanly_disconnected			= 0x2,
			non_blocking_would_have_blocked = 0x3

			/* ... any other info on a "still valid socket" goes here ... */

		};

		///Actual value of the socket_status.
		const values value;

		///Use the default constructor
		socket_status() = default;

		///Construct a "errored/valid" status for a true/false
		socket_status(bool state) :
		 value((values)(state ? valid : errored)) {}

		///Copy socket status by default
		socket_status(const socket_status&) = default;

		///Move socket status by default
		socket_status(socket_status&&) = default;

		///implictly convert this object to const bool (as the status shouldn't change)
		operator const bool() const
		{
			return value != errored;
		}
	};

	///Class that represent a socket
	template <protocol sock_proto, ip ipver = ip::v4>
	class socket
	{
		///Represent a number of bytes with a status information. Some of the methods of this class returns this.
		using bytes_with_status = std::tuple<size_t, socket_status>;

		///OS specific stuff. payload we have to hold onto for RAII management of the Operating System's socket library (e.g. Windows Socket API WinSock2)
		KISSNET_OS_SPECIFIC;

		///operatic-system type for a socket object
		SOCKET sock;

		///Location where this socket is bound
		endpoint bind_loc;

		///Address infomation structures
		addrinfo hints;
		addrinfo* results = nullptr;

		void initialize_addrinfo(int& type, short& familly)
		{
			int iprotocol;
			if constexpr(sock_proto == protocol::tcp)
			{
				type	  = SOCK_STREAM;
				iprotocol = IPPROTO_TCP;
			}
			if constexpr(sock_proto == protocol::udp)
			{
				type	  = SOCK_DGRAM;
				iprotocol = IPPROTO_UDP;
			}

			if constexpr(ipver == ip::v4)
			{
				familly = AF_INET;
			}

			if constexpr(ipver == ip::v6)
			{
				familly = AF_INET6;
			}

			memset(&hints, 0, sizeof hints);
			hints.ai_family   = familly;
			hints.ai_socktype = type;
			hints.ai_protocol = iprotocol;
			hints.ai_flags	= AI_ADDRCONFIG;
		}

		///sockaddr struct
		SOCKADDR sin		  = { 0 };
		sockaddr_storage sout = { 0 };
		socklen_t sout_len;

	public:
		///Construct an invalid socket
		socket() :
		 sock{ INVALID_SOCKET }
		{
		}

		///socket<> isn't copiable
		socket(const socket&) = delete;

		///socket<> isn't copiable
		socket& operator=(const socket&) = delete;

		///Move constructor. socket<> isn't copiable
		socket(socket&& other)
		{
			KISSNET_OS_SPECIFIC_PAYLOAD_NAME = std::move(other.KISSNET_OS_SPECIFIC_PAYLOAD_NAME);
			bind_loc						 = std::move(other.bind_loc);
			sock							 = std::move(other.sock);
			sin								 = std::move(other.sin);
			sout							 = std::move(other.sout);
			sout_len						 = std::move(other.sout_len);

			other.sock = INVALID_SOCKET;
		}

		///Move assign operation
		socket& operator=(socket&& other)
		{

			if(this != &other)
			{

				if(!(sock < 0))
					closesocket(sock);

				KISSNET_OS_SPECIFIC_PAYLOAD_NAME = std::move(other.KISSNET_OS_SPECIFIC_PAYLOAD_NAME);
				bind_loc						 = std::move(other.bind_loc);
				sock							 = std::move(other.sock);
				sin								 = std::move(other.sin);
				sout							 = std::move(other.sout);
				sout_len						 = std::move(other.sout_len);
			}
			return *this;
		}

		///Return true if the underlying OS provided socket representation (file descriptor, handle...). Both socket are pointing to the same thing in this case
		bool operator==(const socket& other) const
		{
			return sock == other.sock;
		}

		///Return true if socket is valid. If this is false, you probably shouldn't attempt to send/receive anything, it will probably explode in your face!
		bool is_valid() const
		{
			return sock != INVALID_SOCKET;
		}

		///Construc socket and (if applicable) connect to the endpoint
		socket(endpoint bind_to) :
		 bind_loc{ bind_to }
		{
			//operating system related housekeeping
			KISSNET_OS_INIT;

			//Do we use streams or datagrams
			int type;
			short familly;
			initialize_addrinfo(type, familly);

			sock = syscall_socket(familly, type, 0);
			if(sock == INVALID_SOCKET)
			{
				kissnet_fatal_error("socket() syscall failed!");
			}

			if(getaddrinfo(bind_loc.address.c_str(), std::to_string(bind_loc.port).c_str(), &hints, &results) != 0)
			{
				kissnet_fatal_error("getaddrinfo failed!");
			}

			//Fill sout with 0s
			memset((void*)&sout, 0, sizeof sout);
		}

		///Construct a socket from an operating system socket, an additional endpoint to remember from where we are
		socket(SOCKET native_sock, endpoint bind_to) :
		 sock{ native_sock }, bind_loc(bind_to)
		{
			KISSNET_OS_INIT;

			short familly;
			int type;

			initialize_addrinfo(type, familly);

			//Fill sout with 0s
			memset((void*)&sout, 0, sizeof sout);
		}

		///Set the socket in non blocking mode
		/// \param state By default "true". If put to false, it will set the socket back into blocking, normal mode
		void set_non_blocking(bool state = true)
		{
			ioctl_setting set = state ? 1 : 0;
			if(ioctlsocket(sock, FIONBIO, &set) < 0)
				kissnet_fatal_error("ioctlsocket returned negative when setting nonblock = " + std::to_string(state));
		}

		///Bind socket locally using hte address and port of the endpoint
		void bind()
		{

			memcpy(&sin, results->ai_addr, sizeof(SOCKADDR));

			if(syscall_bind(sock, (SOCKADDR*)results->ai_addr, results->ai_addrlen) == SOCKET_ERROR)
			{
				kissnet_fatal_error("bind() failed\n");
			}
		}

		///(For TCP) connect to the endpoint as client
		bool connect()
		{
			if constexpr(sock_proto == protocol::tcp) //only TCP is a connected protocol
			{

				memcpy(&sin, results->ai_addr, sizeof(SOCKADDR));

				if(syscall_connect(sock, (SOCKADDR*)&sin, sizeof(SOCKADDR)) != SOCKET_ERROR)
				{
					return true;
				}
				return false;
			}
		}

		///(for TCP= setup socket to listen to connection. Need to be called on binded socket, before being able to accept()
		void listen()
		{
			if constexpr(sock_proto == protocol::tcp)
			{
				if(syscall_listen(sock, SOMAXCONN) == SOCKET_ERROR)
				{
					kissnet_fatal_error("listen failed\n");
				}
			}
		}

		///(for TCP) Wait for incomming connection, return socket connect to the client. Blocking.
		socket accept()
		{
			if constexpr(sock_proto != protocol::tcp)
				return { INVALID_SOCKET, {} };

			SOCKADDR addr;
			SOCKET s	   = INVALID_SOCKET;
			socklen_t size = sizeof addr;

			if((s = syscall_accept(sock, &addr, &size)) == INVALID_SOCKET)
			{
				if(const auto error = get_error_code(); error == EWOULDBLOCK)
					return {};

				kissnet_fatal_error("accept() returned an invalid socket\n");
			}

			return { s, endpoint(&addr) };
		}
		///Close socket on descturction
		~socket()
		{
			if(!(sock == INVALID_SOCKET))
				closesocket(sock);
		}

		template <size_t buff_size>
		bytes_with_status send(const buffer<buff_size>& buff, const size_t length = buff_size)
		{
			assert(buff_size >= length);
			return send(buff.data(), length);
		}

		///Send some bytes through the pipe
		bytes_with_status send(const std::byte* read_buff, size_t lenght)
		{
			int received_bytes;
			if constexpr(sock_proto == protocol::tcp)
			{
				received_bytes = syscall_send(sock, (const char*)read_buff, (buffsize_t)lenght, 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				memcpy(&sin, results->ai_addr, results->ai_addrlen);
				received_bytes = sendto(sock, (const char*)read_buff, (buffsize_t)lenght, 0, (SOCKADDR*)results->ai_addr, results->ai_addrlen);
			}

			if(received_bytes < 0)
			{
				if(get_error_code() == EWOULDBLOCK)
				{
					return { 0, socket_status::non_blocking_would_have_blocked };
				}

				return { 0, socket_status::errored };
			}

			return { received_bytes, socket_status::valid };
		}

		///receive bytes inside the buffer, renturn the number of bytes you got
		template <size_t buff_size>
		bytes_with_status recv(buffer<buff_size>& write_buff)
		{

			auto received_bytes = 0;
			if constexpr(sock_proto == protocol::tcp)
			{
				received_bytes = syscall_recv(sock, (char*)write_buff.data(), (buffsize_t)buff_size, 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				sout_len = sizeof sout;

				received_bytes = ::recvfrom(sock, (char*)write_buff.data(), (buffsize_t)buff_size, 0, (sockaddr*)&sout, &sout_len);
			}

			if(received_bytes < 0)
			{
				if(get_error_code() == EWOULDBLOCK)
					return { 0, socket_status::non_blocking_would_have_blocked };

				return { 0, socket_status::errored };
			}

			if(received_bytes == 0)
			{
				return { received_bytes, socket_status::cleanly_disconnected };
			}

			return { size_t(received_bytes), true };
		}

		///Return the endpoint where this socket is talking to
		endpoint get_bind_loc() const
		{
			return bind_loc;
		}

		///Return an endpoint that originated the data in the last recv
		endpoint get_recv_endpoint() const
		{
			if constexpr(sock_proto == protocol::tcp)
				return get_bind_loc;
			if constexpr(sock_proto == protocol::udp)
			{
				return { (sockaddr*)&sout };
			}
		}

		///Return the number of bytes availabe inside the socket
		size_t bytes_available() const
		{
			static ioctl_setting size = 0;
			auto status				  = ioctlsocket(sock, FIONREAD, &size);

			if(status < 0)
			{
				kissnet_fatal_error("ioctlsocket status is negative when geting FIONREAD\n");
			}

			return size > 0 ? size : 0;
		}

		///Return the protocol used by this socket
		protocol get_protocol() const
		{
			return sock_proto;
		}
	};

	///Alias for socket<protocol::tcp>
	using tcp_socket = socket<protocol::tcp>;
	///Alias for socket<protocol::udp>
	using udp_socket = socket<protocol::udp>;
	///IPV6 versuion of a tcp socket
	using tcp_socket_v6 = socket<protocol::tcp, ip::v6>;
	///IPV6 version of an udp socket
	using udp_socket_v6 = socket<protocol::udp, ip::v6>;
}

#endif //KISS_NET
