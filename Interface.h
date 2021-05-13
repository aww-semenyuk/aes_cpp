#ifndef INTERFACE_H
#define INTERFACE_H

#include "Rijndael.h"


template <typename T>
void PrintHex(const T& obj);

void Encrypt(std::string plaintext, std::string key);


template<typename T>
void PrintHex(const T& obj)
{
	for (const auto& it : obj) {
		std::cout << std::setfill('0') << std::setw(2)
			<< std::hex << static_cast<unsigned int>(static_cast<unsigned char>(it)) << ' ';
	}
}

void Encrypt(std::string plaintext, std::string key)
{
	std::string output;

	std::cout << "AES-" << 32 * Nk << " ENCRYPTION" << std::endl;

	// padding the plaintext
	if (plaintext.size() % BlockLength != 0) {
		plaintext.insert(plaintext.end(), BlockLength - plaintext.size() % BlockLength, 0x00);
	}

	std::cout << "\nPlaintext in hex: " << std::endl;
	PrintHex(plaintext);

	// making the key fit appropriate bit length
	std::array<unsigned char, 4 * Nk> cipher_key;
	if (key.size() % (4 * Nk) != 0 && key.size() < (4 * Nk)) {
		key.insert(key.end(), (4 * Nk) - key.size() % (4 * Nk), 0x00);
	}
	std::copy(key.begin(), key.begin() + 4 * Nk, cipher_key.begin());

	std::cout << "\nKey in hex: " << std::endl;
	PrintHex(cipher_key);

	// encryption process
	for (size_t i = 0; i < plaintext.size() / BlockLength; i++) {
		std::array<unsigned char, BlockLength> block;
		std::copy(plaintext.begin() + BlockLength * i, plaintext.begin() + (BlockLength * i) + BlockLength, block.begin());
		RijndaelBlock tmp(block, cipher_key);
		tmp.performEncryption();
		output += tmp.getEncrypted();
	}

	std::cout << "\nEncrypted text: " << std::endl;
	PrintHex(output);
	std::cout << std::endl;
}

#endif // !INTERFACE_H