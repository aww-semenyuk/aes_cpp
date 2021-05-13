#include <iostream>
#include <chrono>
#include <string>
#include "Interface.h"

int main()
{
	std::string input;
	std::string key;

	std::cout << "Enter text to be encrypted: ";
	std::getline(std::cin, input);

	std::cout << "Enter the key: ";
	std::getline(std::cin, key);

	std::cout << std::endl;

	auto start = std::chrono::high_resolution_clock::now();
	Encrypt(input, key);
	auto end = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double> duration = end - start;
	std::cout << "Encryption time: " << duration.count() << "s" << std::endl;	

	system("pause");
	return 0;
}