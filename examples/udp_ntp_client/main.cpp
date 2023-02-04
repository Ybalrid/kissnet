#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>
#include <csignal>
#include <kissnet.hpp>
#include <chrono>
using namespace std::chrono_literals;

namespace kn = kissnet;

int main(int argc, char* argv[])
{

	// NTP uses port 123
	kn::port_t port = 123;

	{
		//Create a kissnet tcp ipv4 socket
		kn::udp_socket a_socket(kn::endpoint("time.apple.com", port));

		unsigned char msg[48]={010, 0, 0, 0, 0, 0, 0, 0, 0};

		//Send request
		a_socket.send(reinterpret_cast<const std::byte*>(msg), 48);

		//Receive data into a buffer
		kn::buffer<4096> static_buffer;

		while (true) { // wait for a response from server
			std::this_thread::sleep_for(1s);

			if (a_socket.bytes_available() >= 48) { // expect 48 bytes back
				//Get the data, and the lengh of data
				const auto [data_size, status_code] = a_socket.recv(static_buffer);
				const unsigned int *arr = reinterpret_cast<const unsigned int*>(static_buffer.data());
				time_t t = ntohl((time_t)arr[10]);
				t -= 2208988800U; // subtract epoch

				printf("Time: %s",ctime(&t));
				break;
			}
		}
	}

	return 0;
}
