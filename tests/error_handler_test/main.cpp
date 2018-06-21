#include <iostream>
#include <kissnet.hpp>

int main()
{
	kissnet::error::abortOnError = false;

	kissnet::error::handler("test what code would be called on error when built without exception\n");

	kissnet::error::callback = [](const std::string& str, void* ctx)
	{
		std::cerr << "this is the callback : ";
		std::cerr << str;
		(void)ctx;
	};


	kissnet::error::handler("test our custom callback");


    return 0;
}
