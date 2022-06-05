#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>
#include <csignal>
#include <kissnet.hpp>

namespace kn = kissnet;

int main(int argc, char* argv[])
{

	//Configuration (by default)
	kn::port_t port = 12321;
	//If specified : get port from command line
	if (argc >= 2)
	{
		port = kn::port_t(strtoul(argv[1], nullptr, 10));
	}

	//We need to store thread objects somewhere:
	std::vector<std::thread> threads;

	//Create a listening TCP socket on requested port
	kn::tcp_socket& listen_socket = kn::tcp_socket::get({ "0.0.0.0", port });
	listen_socket.bind();
	listen_socket.listen();

	//close program upon ctrl+c or other signals
	std::signal(SIGINT, [](int) {
		std::cout << "Got sigint signal...\n";
		std::exit(0);
	});

	//Send the SIGINT signal to ourself if user press return on "server" terminal
	std::thread run_th([] {
		std::cout << "press return to close server...\n";
		std::cin.get(); //This call only returns when user hit RETURN
		std::cin.clear();
		std::raise(SIGINT);
	});

	//Let that thread run alone
	run_th.detach();

	//Loop that continously accept connections
	while (true)
	{
		std::cout << "Waiting for a client on port " << port << '\n';
		listen_socket.accept([&](kn::tcp_socket& sock)
		{
			//Create thread that will echo bytes received to the client
			threads.emplace_back([&] {
				//Internal loop
				bool continue_receiving = true;
				//Static 1k buffer
				kn::buffer<1024> buff;

				//While connection is alive
				while (continue_receiving)
				{
					//attept to receive data
					if (auto [size, valid] = sock.recv(buff); valid)
					{
						if (valid.value == kn::socket_status::cleanly_disconnected)
							continue_receiving = false;
						else
							sock.send(buff.data(), size);
					}
					//If not valid remote host closed conection
					else
					{
						continue_receiving = false;
					}
				}
			});

			threads.back().detach();
		});
	}

	return 0;
}
