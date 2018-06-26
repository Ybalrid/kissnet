# kissnet

**K**eep **I**t **S**imple **S**tupid **NET**work.

A lightweight, header only, crossplatform C++17 socket library.

Wrap all annoying C api calls to the OS inside a `socket` template class

## Features:

* Stupidly simple
* TCP socket
* UDP socket
* ipv4 and ipv6 support
* Error reporting with and without exceptions
  * You can deactivate exception support. If you do so, library will by default log to `stderr` (without `iostream`), and abort program
  * You can provide a custom error handling callback, and you can deactivate the automatic abort by the error handler
* Communicate with buffers of C++17 `std::byte`
* Manage required library (e.g. WinSock2) initialization and cleanup for you RAII style. Network is de-initialized when last socket object goes out of scope
* Use familiar names for socket operations as methods: `send`, `recv`, `connect`, `bind`, `listen`, `accept`...

## Short docs

*Volontary contrived examples showing how the library looks like:*

You can take a look a some of the programs in the `examples` directory

 * Basic client usage, tcp connect and read, udp send, udp read

```cpp
#include <iostream>
#include <thread>
#include <chrono>

#include <kissnet.hpp>
using namespace std::chrono_literals;
namespace kn = kissnet;

int main()
{
	{
		//Create a kissnet tco ipv4 socket
		kn::tcp_socket a_socket(kn::endpoint("avalon.ybalrid.info:80"));
		a_socket.connect();

		//Create a "GET /" HTTP request, and send that packet into the socket
		auto get_index_request = std::string{ "GET / HTTP/1.1\r\nHost: avalon.ybalird.info\r\n\r\n" };

		//Send request
		a_socket.send(reinterpret_cast<const std::byte*>(get_index_request.c_str()), get_index_request.size());

		//Receive data into a buffer
		kn::buffer<4096> static_buffer;

		//Useless wait, just to show how long the response was
		std::this_thread::sleep_for(1s);

		//Print how much data our OS has for us
		std::cout << "bytes available to read : " << a_socket.bytes_available() << '\n';

		//Get the data, and the lengh of data
		const auto data_size = a_socket.recv(static_buffer);

		//To print it as a good old C string, add a null terminator
		if(data_size < static_buffer.size())
			static_buffer[data_size] = std::byte{ '\0' };

		//Print the raw data as text into the terminal (should display html/css code here)
		std::cout << reinterpret_cast<const char*>(static_buffer.data()) << '\n';
	}

	/*No more socket here, this will actually close WSA on Windows*/

	{
		//Socket used to send, the "endpoint" is the destination of the data
		kn::udp_socket a_socket(kn::endpoint("127.0.0.1", 6666));

		//Socket used to receive, the "endpoint" is where to listen to data
		kn::udp_socket b_socket(kn::endpoint("0.0.0.0", 6666));
		b_socket.bind();

		//Byte buffer
		kn::buffer<16> buff;

		//Build data to send (flat array of bytes
		for(unsigned char i = 0; i < 16; i++)
			buff[i] = std::byte{ i };

		//Send data
		a_socket.send(buff.data(), 16);

		//Same deal as above
		std::this_thread::sleep_for(1s);

		//We do know, for the sake of the example, that there are 16 bytes to get from the network
		kn::buffer<16> recv_buff;

		//Actually print bytes_available
		std::cout << "avaliable in UDP socket : " << b_socket.bytes_available() << " bytes\n";

		//You receive in the same way
		b_socket.recv(recv_buff);
		const auto from = b_socket.get_recv_endpoint();

		//Print the data
		std::cout << "Received: ";

		for(unsigned char i = 0; i < 16; i++)
		{
			std::cout << std::hex << std::to_integer<int>(recv_buff[i]) << std::dec << ' ';
		}

		//Print who send the data
		std::cout << "From: " << from.address << ' ' << from.port << '\n';
	}

	//So long, and thanks for all the fish
	return 0;

```

 * TCP listener

```cpp

#include <kissnet.hpp>
#include <iostream>

namespace kn = kissnet;

int main()
{
	//setup socket
	kn::socket<kissnet::protocol::tcp> server(kn::endpoint("0.0.0.0:8080"));
	server.bind();
	server.listen();

	//Wait for one co
	auto client = server.accept();

	//Read once in a 1k buffer
	kn::buffer<1024> buff;
	const auto size = client.recv(buff);

	//Add null terminator, and print as string
	if(size < buff.size()) buff[size] = std::byte{ 0 };
	std::cout << reinterpret_cast<const char*>(buff.data()) << '\n';

	return 0;
}

```
