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