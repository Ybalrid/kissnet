#include <iostream>
#include <kissnet.hpp>

int main()
{
    //Create a kissnet socket
    kissnet::socket<kissnet::protocol::tcp> a_socket(kissnet::endpoint("avalon.ybalrid.info:80"));
    
    //Create a "GET /" HTTP request, and send that packet into the socket
    auto get_index_request = std::string { "GET / HTTP/1.1\r\nHost: avalon.ybalird.info\r\n\r\n"};
    a_socket.send((std::byte*) get_index_request.c_str(), get_index_request.size());

    //Receive data into a buffer
    kissnet::buffer<4096> static_buffer;
    a_socket.recv(static_buffer);
    
    //Print the raw data as text into the terminal
    std::cout << (char*)static_buffer.data() << '\n';
    return 0;
}
