#ifndef KISS_NET
#define KISS_NET

#include <array>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

///Main namespace of kissnet
namespace kissnet
{
	using namespace std::string_literals;

	namespace error
	{
		struct cant_create_endpoint : public std::runtime_error
		{
			cant_create_endpoint(std::string error) :
			 std::runtime_error("Cannot create endpoint "s + error)
			{}
		};
	}

	///stash all the global C crap from the operating system inside kissnet::os::
	namespace os
	{
#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

		//Handle WinSock2/Windows Socket API initialziation and cleanup
#pragma comment(lib, "Ws2_32.lib")
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
				WSAStartup(MAKEWORD(2, 2) n & wsa_data);
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

#define KISSNET_OS_SPECIFIC std::shared_ptr<WSA> wsa_ptr
#define KISSNET_OS_INIT wsa_ptr = getWSA()
#else //UNIX platform

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

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

#define KISSNET_OS_SPECIFIC
#define KISSNET_OS_INIT

#endif
	}

	///low level protocol used, between TCP and UDP
	enum class protocol { tcp,
						  udp };

	///Byte buffer
	template <size_t buff_size>

	///buffer is an array of std::byte
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
			port	= strtoul(addr.substr(separator + 1).c_str(), nullptr, 10);
		}
	};

	///Class that represent a socket
	template <protocol sock_proto>
	class socket
	{
		///OS specific stuff
		KISSNET_OS_SPECIFIC;

		///Location where this socket is bound
		endpoint bind_loc;

		///operatic-system type for a socket object
		os::SOCKET sock;

		///hostinfo structure
		os::hostent* hostinfo = nullptr;

		///sockaddr struct
		os::SOCKADDR_IN sin = { 0 };
		os::SOCKADDR sout   = { 0 };
		os::socklen_t sout_len;

	public:
		///Construc socket and (if applicable) connect to the endpoint
		socket(endpoint bind_to) :
		 bind_loc{ bind_to }
		{
			//Do we use streams or datagrams
			int type;
			if constexpr(sock_proto == protocol::tcp)
			{
				type = os::SOCK_STREAM;
			}
			if constexpr(sock_proto == protocol::udp)
			{
				type = os::SOCK_DGRAM;
			}

			KISSNET_OS_INIT;

			sock = os::socket(AF_INET, type, 0);
			if(sock == os::INVALID_SOCKET)
			{
				//error here
				std::cerr << "invalid socket\n";
			}

			hostinfo = os::gethostbyname(bind_loc.address.c_str());
			if(!hostinfo)
			{
				//error here
				std::cerr << "hostinfo is null\n";
			}

			sin.sin_addr   = *(os::IN_ADDR*)hostinfo->h_addr;
			sin.sin_port   = os::htons(bind_loc.port);
			sin.sin_family = AF_INET;

			if constexpr(sock_proto == protocol::tcp)
			{
				if(os::connect(sock, (os::SOCKADDR*)&sin, sizeof(os::SOCKADDR)) == os::SOCKET_ERROR)
				{
					//error here
					std::cerr << "connect failed\n";
				}
			}

			if constexpr(sock_proto == protocol::udp)
			{
				if(os::bind(sock, (os::SOCKADDR*)&sin, sizeof(os::SOCKADDR)) < 0)
				{
					//error here
					std::cerr << "bind failed";
				}
			}
			int set = 1;
			os::ioctlsocket(sock, FIONBIO, &set);

			//Fill sout with 0s
			memset((void*)&sout, 0, sizeof sout);
		}

		///Close socket on descturction
		~socket()
		{
			if(!(sock < 0))
				os::closesocket(sock);
		}

		///Send some bytes through the pipe
		void send(std::byte* read_buff, size_t lenght)
		{
			if constexpr(sock_proto == protocol::tcp)
			{
				os::send(sock, read_buff, lenght, 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				os::sendto(sock, read_buff, lenght, 0, (os::SOCKADDR*)&sin, sizeof sin);
			}
		}

		///receive bytes inside the buffer, renturn the number of bytes you got
		template <size_t buff_size>
		size_t recv(buffer<buff_size>& write_buff)
		{

			auto n = 0;
			if constexpr(sock_proto == protocol::tcp)
			{
				n = os::recv(sock, write_buff.data(), buff_size, 0);
			}

			if constexpr(sock_proto == protocol::udp)
			{
				n = os::recvfrom(sock, write_buff.data(), buff_size, 0, &sout, &sout_len);
			}

			if(n < 0)
			{
				//error here
				std::cout << "recv is negative\n";
			}

			return n;
		}

		///Return the endpoint where this socket is talking to
		endpoint get_bind_loc()
		{
			return get_bind_loc();
		}

		///Return an endpoint that originated the data in the last recv
		endpoint get_recv_endpoint()
		{
			if constexpr(sock_proto == protocol::tcp)
				return get_bind_loc;
			if constexpr(sock_proto == protocol::udp)
			{
				auto ip_sout = reinterpret_cast<os::SOCKADDR_IN*>(&sout);
				return { os::inet_ntoa(ip_sout->sin_addr), ip_sout->sin_port };
			}
		}

		///Return the number of bytes availabe inside the socket
		size_t bytes_available()
		{
			static auto size = 0;
			auto status		 = os::ioctlsocket(sock, FIONREAD, &size);

			if(status < 0)
			{
				//error here?
				std::cerr << "ioctlsocket status is negative\n";
			}

			return size > 0 ? size : 0;
		}
	};
}

#endif //KISS_NET
