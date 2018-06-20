#include <iostream>
#include <kissnet.hpp>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

int main()
{
	{
		//Create a kissnet socket
		kissnet::socket<kissnet::protocol::tcp> a_socket(kissnet::endpoint("avalon.ybalrid.info:80"));

		//Create a "GET /" HTTP request, and send that packet into the socket
		auto get_index_request = std::string{ "GET / HTTP/1.1\r\nHost: avalon.ybalird.info\r\n\r\n" };
		a_socket.send((std::byte*)get_index_request.c_str(), get_index_request.size());

		//Receive data into a buffer
		kissnet::buffer<4096> static_buffer;

		std::this_thread::sleep_for(1s);
		std::cout << "bytes available to read : " << a_socket.bytes_available() << '\n';

		const auto data_size = a_socket.recv(static_buffer);

		if(data_size < static_buffer.size())
		{
			static_buffer[data_size] = std::byte{ '\0' };
		}
		//Print the raw data as text into the terminal
		std::cout << (char*)static_buffer.data() << '\n';
	}

	{
		kissnet::socket<kissnet::protocol::udp> a_socket(kissnet::endpoint("127.0.0.1", 6666));
		kissnet::socket<kissnet::protocol::udp> b_socket(kissnet::endpoint("127.0.0.1", 6666));
		b_socket.bind();
		
		kissnet::buffer<16> buff;

		for(unsigned char i = 0; i < 16; i++)
			buff[i] = std::byte{ i };

		a_socket.send(buff.data(), 16);

		kissnet::buffer<16> recv_buff;

		std::this_thread::sleep_for(1s);

		std::cout << "avaliable in UDP socket : " << b_socket.bytes_available() << " bytes\n";
		b_socket.recv(recv_buff);
		auto from = b_socket.get_recv_endpoint();

		std::cout << "Received: ";

		for(unsigned char i = 0; i < 16; i++)
		{
			std::cout << std::hex << std::to_integer<int>(recv_buff[i]) << std::dec << ' ';
		}

		std::cout << "From: " << from.address << ' ' << from.port << '\n';
	}

	return 0;
}
