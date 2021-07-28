#include <iostream>
#include <thread>
#include <vector>

#include <kissnet.hpp>

// The test creates a UDP server listening on all interfaces port 5555
// and two clients sending data (16 bytes) to the server.
// Client 1 sets byte 0 to 1 and client 2 sets byte 0 to 2
// when the server receives the data it sets byte 1 to 3 and returns the 16 bytes
// Client 1 should receive byte 0 == 1 and byte 1 == 3
// Client 2 should receive byte 0 == 2 and byte 1 == 3
// The test is using the optional
// sockaddr_storage from_who = {}; from the receive and re using that when returning the data
// to the clients so that the response trough for example NAT get traversed correctly.

//
bool client_1_fail = true;
bool client_2_fail = true;

bool server_running = false;

kissnet::udp_socket server_socket;

void client_1(const std::string& target_ip) {
    std::cout << "Client 1 started" << std::endl;
    kissnet::buffer<16> send_buff = {static_cast<std::byte>(0)};
    send_buff[0] = static_cast<std::byte>(1);
    while (!server_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "Client 1 push data to server" << std::endl;
    kissnet::udp_socket client1_socket(kissnet::endpoint(target_ip, 5555));
    client1_socket.send(send_buff);
    auto[received_bytes, status] = client1_socket.recv(send_buff);
    std::cout << "Client 1 got data from server" << std::endl;
    if (received_bytes == 16 && status == kissnet::socket_status::valid) {
        if (send_buff[0] == static_cast<std::byte>(1) && send_buff[1] == static_cast<std::byte>(3)) {
            client_1_fail = false;
        }
    }
    std::cout << "End client1" << std::endl;
}

void client_2(const std::string& target_ip) {
    std::cout << "Client 2 started" << std::endl;
    kissnet::buffer<16> send_buff = {static_cast<std::byte>(0)};
    send_buff[0] = static_cast<std::byte>(2);
    while (!server_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "Client 2 push data to server" << std::endl;
    kissnet::udp_socket client2_socket(kissnet::endpoint(target_ip, 5555));
    client2_socket.send(send_buff);
    auto[received_bytes, status] = client2_socket.recv(send_buff);
    std::cout << "Client 2 got data from server" << std::endl;
    if (received_bytes == 16 && status == kissnet::socket_status::valid) {
        if (send_buff[0] == static_cast<std::byte>(2) && send_buff[1] == static_cast<std::byte>(3)) {
            client_2_fail = false;
        }
    }
    std::cout << "End client2" << std::endl;
}

void server(const std::string& server_ip) {
    std::cout << "Server started" << std::endl;
    kissnet::buffer<16> recv_buff;
    kissnet::udp_socket new_server_socket(kissnet::endpoint(server_ip, 5555));
    server_socket = std::move(new_server_socket);
    server_socket.bind();
    server_running = true;
    while (true) {
        kissnet::addr_collection addr;
        auto[received_bytes, status] = server_socket.recv(recv_buff, 0, &addr);
        if (!received_bytes || status != kissnet::socket_status::valid) {
            break;
        }
        std::cout << "Server got data" << std::endl;
        recv_buff[1] = static_cast<std::byte>(3);
        server_socket.send(recv_buff, 16, &addr);
    }
    std::cout << "End server" << std::endl;
}

int main()
{

    //Test IPv4
    std::thread ipv4_t1 (server, "0.0.0.0");
    std::thread ipv4_t2 (client_1, "127.0.0.1");
    std::thread ipv4_t3 (client_2, "127.0.0.1");
    ipv4_t2.join();
    ipv4_t3.join();
    server_socket.shutdown();
    server_socket.close();
    ipv4_t1.join();
    if (client_1_fail || client_2_fail) {
        return EXIT_FAILURE;
    }

    server_running = false;
    client_1_fail = true;
    client_2_fail = true;

    //Test IPv6
    std::thread ipv6_t1 (server, "::");
    std::thread ipv6_t2 (client_1, "::1");
    std::thread ipv6_t3 (client_2, "::1");
    ipv6_t2.join();
    ipv6_t3.join();
    server_socket.shutdown();
    server_socket.close();
    ipv6_t1.join();
    if (client_1_fail || client_2_fail) {
        return EXIT_FAILURE;
    }

	//So long, and thanks for all the fish
	return EXIT_SUCCESS;
}
