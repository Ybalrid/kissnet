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

	struct WSA;
	namespace internal_state
	{
		static WSA* global_WSA = nullptr;
	}

	struct WSA : std::enable_shared_from_this<WSA>
	{
		WSADATA wsa_data;
		WSA()
		{
			WSAStartup(MAKEWORD(2, 2), &wsa_data);
		}

		~WSA()
		{
			WSACleanup();
			internal_state::global_WSA = nullptr;
		}

		std::shared_ptr<WSA> getPtr()
		{
			return shared_from_this();
		}
	};

	std::shared_ptr<WSA> getWSA()
	{
		if(internal_state::global_WSA)
			return internal_state::global_WSA->getPtr();

		//Create shared_ptr
		auto wsa = std::make_shared<WSA>();

		internal_state::global_WSA = wsa.get();
		return wsa;
	}

#define KISSNET_OS_SPECIFIC_PAYLOAD_NAME wsa_ptr
#define KISSNET_OS_SPECIFIC std::shared_ptr<kissnet::WSA> KISSNET_OS_SPECIFIC_PAYLOAD_NAME
#define KISSNET_OS_INIT KISSNET_OS_SPECIFIC_PAYLOAD_NAME = kissnet::getWSA()

	int get_error_code()
	{
		return WSAGetLastError();
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

int get_error_code()
{
	return errno;
}

#endif

///Main namespace of kissnet
namespace kissnet
{
	using namespace std::string_literals;

	namespace error
	{
		static void (*callback)(const std::string&, void* ctx) = nullptr;
		static void* ctx									   = nullptr;
		static bool abortOnError							   = true;

		void handler(const std::string& str)
		{
			if(callback)
			{
				callback(str, ctx);
			}
			else
			{
				fputs(str.c_str(), stderr);
			}

			if(abortOnError)
			{
				abort();
			}
		}
	}

	///low level protocol used, between TCP and UDP
	enum class protocol { tcp,
						  udp };

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

		endpoint(SOCKADDR addr)
		{
			SOCKADDR_IN ip_addr = *(SOCKADDR_IN*)(&addr);
			address				= inet_ntoa(ip_addr.sin_addr);
			port				= ip_addr.sin_port;
		}
	};

	//Wrap "system calls" here to avoid conflicts with the names used in the socket class
	auto syscall_socket  = [](int af, int type, int protocol) { return socket(af, type, protocol); };
	auto syscall_recv	= [](SOCKET s, char* buff, buffsize_t len, int flags) { return recv(s, buff, len, flags); };
	auto syscall_send	= [](SOCKET s, const char* buff, buffsize_t len, int flags) { return send(s, buff, len, flags); };
	auto syscall_bind	= [](SOCKET s, const struct sockaddr* name, socklen_t namelen) { return bind(s, name, namelen); };
	auto syscall_connect = [](SOCKET s, const struct sockaddr* name, socklen_t namelen) { return connect(s, name, namelen); };
	auto syscall_listen  = [](SOCKET s, int backlog) { return listen(s, backlog); };
	auto syscall_accept  = [](SOCKET s, struct sockaddr* addr, socklen_t* addrlen) { return accept(s, addr, addrlen); };

	///Class that represent a socket
	template <protocol sock_proto, ip ipver = ip::v4>
	class socket
	{
		struct bytes_with_status
		{
			size_t bytes;
			bool no_error;
		};

		///OS specific stuff. payload we have to hold onto for RAII management of the Operating System's socket library (e.g. Windows Socket API WinSock2)
		KISSNET_OS_SPECIFIC;

		///operatic-system type for a socket object
		SOCKET sock;

		///Location where this socket is bound
		endpoint bind_loc;

		///hostinfo structure
		hostent* hostinfo = nullptr;

		///sockaddr struct
		SOCKADDR_IN sin = { 0 };
		SOCKADDR sout   = { 0 };
		socklen_t sout_len;

		socket() = default;

	public:
		socket(const socket&) = delete;
		socket& operator=(const socket&) = delete;

		socket(socket&& other)
		{
			KISSNET_OS_SPECIFIC_PAYLOAD_NAME = std::move(other.KISSNET_OS_SPECIFIC_PAYLOAD_NAME);
			bind_loc						 = std::move(other.bind_loc);
			sock							 = std::move(other.sock);
			sin								 = std::move(other.sin);
			sout							 = std::move(other.sout);
			sout_len						 = std::move(other.sout_len);

			other.sock = -1;
		}

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

		bool operator==(const socket& other)
		{
			return sock == other.sock;
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
			if constexpr(sock_proto == protocol::tcp)
			{
				type = SOCK_STREAM;
			}
			if constexpr(sock_proto == protocol::udp)
			{
				type = SOCK_DGRAM;
			}

			if constexpr(ipver == ip::v4)
			{
				familly = AF_INET;
			}

			if constexpr(ipver == ip::v6)
			{
				familly = AF_INET6;
			}

			sock = syscall_socket(familly, type, 0);
			if(sock == INVALID_SOCKET)
			{
				//error here
				//std::cerr << "invalid socket\n";
			}

			hostinfo = gethostbyname(bind_loc.address.c_str());
			if(!hostinfo)
			{
				//error here
				//std::cerr << "hostinfo is null\n";
			}

			sin.sin_addr   = *(IN_ADDR*)hostinfo->h_addr;
			sin.sin_port   = htons(bind_loc.port);
			sin.sin_family = familly;

			//ioctl_setting set = 1;
			//ioctlsocket(sock, FIONBIO, &set);

			//Fill sout with 0s
			memset((void*)&sout, 0, sizeof sout);
		}

		///Construct a socket from an operating system socket, an additional endpoint to remember from where we are
		socket(SOCKET native_sock, endpoint bind_to) :
		 sock{ native_sock }, bind_loc(bind_to)
		{

			short familly;

			if constexpr(ipver == ip::v4)
			{
				familly = AF_INET;
			}

			if constexpr(ipver == ip::v6)
			{
				familly = AF_INET6;
			}

			hostinfo = gethostbyname(bind_loc.address.c_str());
			if(!hostinfo)
			{
				kissnet_fatal_error("hostinfo is null\n");
			}

			sin.sin_addr   = *(IN_ADDR*)hostinfo->h_addr;
			sin.sin_port   = htons(bind_loc.port);
			sin.sin_family = familly;
		}

		///Bind socket locally using hte address and port of the endpoint
		void bind()
		{

			if(syscall_bind(sock, (SOCKADDR*)&sin, sizeof(SOCKADDR)) == SOCKET_ERROR)
			{
				kissnet_fatal_error("bind() failed\n");
			}
		}

		///(For TCP) connect to the endpoint as client
		bool connect()
		{
			if constexpr(sock_proto == protocol::tcp) //only TCP is a connected protocol
			{
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
				kissnet_fatal_error("accept() returned an invalid socket\n");
			}

			return { s, endpoint(addr) };
		}
		///Close socket on descturction
		~socket()
		{
			if(!(sock < 0))
				closesocket(sock);
		}

		///Send some bytes through the pipe
		size_t send(const std::byte* read_buff, size_t lenght)
		{
			if constexpr(sock_proto == protocol::tcp)
			{
				return syscall_send(sock, (const char*)read_buff, (buffsize_t)lenght, 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				return sendto(sock, (const char*)read_buff, (buffsize_t)lenght, 0, (SOCKADDR*)&sin, sizeof sin);
			}
		}

		///receive bytes inside the buffer, renturn the number of bytes you got
		template <size_t buff_size>
		bytes_with_status recv(buffer<buff_size>& write_buff)
		{

			auto n		= 0;
			bool status = true;
			if constexpr(sock_proto == protocol::tcp)
			{
				n = syscall_recv(sock, (char*)write_buff.data(), (buffsize_t)write_buff.size(), 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				sout_len = sizeof sout;
				n		 = recvfrom(sock, (char*)write_buff.data(), (buffsize_t)write_buff.size(), 0, &sout, &sout_len);
			}

			if(n < 0)
			{
				status = false;
			}

			if(n == 0)
			{
				//connection closed by remote? callback?
			}
			return { (size_t)(n < 0 ? 0 : n), status };
		}

		///Return the endpoint where this socket is talking to
		endpoint get_bind_loc() const
		{
			return bind_loc;
		}

		///Return an endpoint that originated the data in the last recv
		endpoint get_recv_endpoint()
		{
			if constexpr(sock_proto == protocol::tcp)
				return get_bind_loc;
			if constexpr(sock_proto == protocol::udp)
			{
				return { sout };
			}
		}

		///Return the number of bytes availabe inside the socket
		size_t bytes_available()
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
}

#endif //KISS_NET
