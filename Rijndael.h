#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <iostream>
#include <iomanip>
#include <array>
#include <string>

// Rijndael is a symmetric block cipher that can process data blocks of 128 bits,
// using cipher keys with lengths of 128, 192, and 256 bits (specified as AES-128, AES-192 and AES-256)

// Nb - number of columns (32-bit words) comprising the state
// Nk - number of 32-bit words comprising the Cypher Key
// Nr - number of rounds performed (function of Nb and Nk)



#define AES128

#define Nb 4
#define BlockLength (4 * Nb)

#ifdef AES128
#define Nk 4
#define Nr 10

#elif defined AES192
#define Nk 6
#define Nr 12

#elif defined AES256
#define Nk 8
#define Nr 14

#endif


class RijndaelBlock
{
private:
	typedef std::array<unsigned char, 4 * Nk> key_arr;
	typedef std::array<unsigned char, 4 * Nb> block_arr;
	typedef std::array<unsigned char, 4 * Nb * (Nr + 1)> exp_key_arr;
	typedef std::array<std::array<unsigned char, Nb>, 4> state_grid;

	void SubBytes();
	void ShiftRows();
	void MixColumns();
	void AddRoundKey(size_t round_number);

	void KeyExpansion();

public:
	RijndaelBlock(const block_arr& plaintext, const key_arr& key);
	void performEncryption();
	std::string getEncrypted() const;

private:
	bool isPerformed; // flag which shows if encryption has already been performed
	state_grid state; // 4 by 4 grid representing input text block
	key_arr cipher_key; // 16, 24 or 32 byte length cipher key
	exp_key_arr expanded_key; // 176, 208 or 240 byte length sequence of round keys
	block_arr encrypted; // 16 byte length encrypted text block
};

#endif // !RIJNDAEL_H