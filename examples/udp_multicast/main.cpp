#include <iostream>
#include <thread>
#include <kissnet.hpp>

const auto global_mcast_addr = "226.1.1.1"; //IPv4
//const auto global_mcast_addr = "ff12::1234"; //IPv6
const uint64_t global_mcast_port = 9000;
bool global_thread_running		 = true;
bool global_thread_stopped = false;
const std::string global_message = "This is a multicast message payload";

void send_multicast_data(){
	std::cout << "kissnet multicast send thread started" << std::endl;
	//Max IPv6 UDP payload is 1452.. IPv4 is 1472
	kissnet::buffer<1452> send_this;
	std::memcpy(send_this.data(), global_message.c_str(), global_message.size());

	//Tell kissnet where to send the multicast packets

	kissnet::udp_socket mcast_send_socket(kissnet::endpoint(global_mcast_addr, global_mcast_port));
	while (global_thread_running) {
		//Send the payload
		auto[sent_bytes, status] = mcast_send_socket.send(send_this, sizeof(send_this));
		if (sent_bytes != sizeof(send_this) || status != kissnet::socket_status::valid) {
			std::cout << "kissnet multicast send failure" << std::endl;
			break;
		}
		std::cout << "Sent multicast packet." << std::endl;

		//Wait for 100 milliseconds
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	//The thread will exit
	mcast_send_socket.close();
	std::cout << "kissnet multicast send thread ended" << std::endl;
	global_thread_stopped = true;
}

int main(int argc, char* argv[])
{
	std::cout << "kissnet multicast example" << std::endl;

	//Detach the multicast seander thread
	std::thread([=]() { send_multicast_data(); }).detach();
	//Let the thread start and the client spit out som packages before we join the multicast
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	//Create a socket and join a multicast
	auto mcast_listen_socket = kissnet::udp_socket();
	mcast_listen_socket.join(kissnet::endpoint(global_mcast_addr, global_mcast_port));

	kissnet::buffer<4000> receive_buffer;

	//Get 100 packets
	for (int a = 0; a < 100; a++) {
		auto [received_bytes, status] = mcast_listen_socket.recv(receive_buffer);
		if (!received_bytes || status != kissnet::socket_status::valid) {
			std::cout << "Failed getting multicast data" << std::endl;
		}
		//Did we get the correct payload
		uint64_t character_position = 0;
		for(const char& c : global_message) {
			if (c != (char)receive_buffer[character_position++]) {
				std::cout << "Data missmatch " << std::endl;
			}
		}
		std::cout << "Got multicast data of size " << received_bytes << std::endl;
	}
	//Now done signal stop exit thread and get out of here.
	global_thread_running = false;
	while (!global_thread_stopped) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	mcast_listen_socket.close();
	return 0;
}
