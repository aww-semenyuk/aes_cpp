#include "Rijndael.h"
#include "Tables.h"

RijndaelBlock::RijndaelBlock(const block_arr& plaintext, const key_arr& key) : isPerformed(false)
{
	// forming a state grid
	for (size_t i = 0; i < Nb; i++) {
		for (size_t j = 0; j < 4; j++) {
			state[j][i] = plaintext[i * 4 + j];
		}
	}
	// copying the key
	std::copy(std::begin(key), std::end(key), std::begin(cipher_key));
}

void RijndaelBlock::performEncryption()
{
	// checking if encryption has already been performed
	if (isPerformed == true) {
		std::cout << "This block is already encrypted!" << std::endl;
		return;
	}

	// performing key expansion routine
	KeyExpansion();

	// initial round
	AddRoundKey(0);

	// main rounds
	for (size_t i = 1; i < Nr; i++) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(i);
	}

	// final round
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);

	// forming an encrypted block
	for (size_t i = 0; i < Nb; i++) {
		for (size_t j = 0; j < 4; j++) {
			encrypted[i * 4 + j] = state[j][i];
		}
	}

	isPerformed = true;
}

void RijndaelBlock::KeyExpansion()
{
	std::array<unsigned char, 4> tmp;

	// using the primary key for the first round
	std::copy(std::begin(cipher_key), std::end(cipher_key), std::begin(expanded_key));

	// each subsequent round key is deduced from previously deduced round keys
	for (size_t i = Nk; i < (Nb * (Nr + 1)); i++) {
		for (size_t j = 0; j < 4; j++) { // getting previous column as it is
			tmp[j] = expanded_key[(i - 1) * 4 + j];
		}

		// if column number is divisible by keylength
		if (i % Nk == 0) {

			// rotating element by 1 to the left
			unsigned char k = tmp[0];
			tmp[0] = tmp[1];
			tmp[1] = tmp[2];
			tmp[2] = tmp[3];
			tmp[3] = k;

			// applying Sbox to the column
			tmp[0] = Sbox[tmp[0]];
			tmp[1] = Sbox[tmp[1]];
			tmp[2] = Sbox[tmp[2]];
			tmp[3] = Sbox[tmp[3]];

			tmp[0] ^= Rcon[i / Nk]; // xor-ing with rcon
		}

		else if (Nk > 6 && i % Nk == 4) {

			// applying Sbox to the column
			tmp[0] = Sbox[tmp[0]];
			tmp[1] = Sbox[tmp[1]];
			tmp[2] = Sbox[tmp[2]];
			tmp[3] = Sbox[tmp[3]];
		}

		// xor-ing with column with i-KeyLength index to get a expanded key column
		expanded_key[i * 4 + 0] = expanded_key[(i - Nk) * 4 + 0] ^ tmp[0];
		expanded_key[i * 4 + 1] = expanded_key[(i - Nk) * 4 + 1] ^ tmp[1];
		expanded_key[i * 4 + 2] = expanded_key[(i - Nk) * 4 + 2] ^ tmp[2];
		expanded_key[i * 4 + 3] = expanded_key[(i - Nk) * 4 + 3] ^ tmp[3];
	}
}

void RijndaelBlock::AddRoundKey(size_t round_number)
{
	// simply xor-ing the state with appropriate round key
	for (size_t i = 0; i < Nb; i++) {
		for (size_t j = 0; j < 4; j++) {
			state[j][i] ^= expanded_key[round_number * BlockLength + i * Nb + j];
		}
	}
}

void RijndaelBlock::SubBytes()
{
	// finding an equivalent from Sbox for every byte of state
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < Nb; j++) {
			state[i][j] = Sbox[state[i][j]];
		}
	}
}

void RijndaelBlock::ShiftRows()
{
	unsigned char tmp;

	// moving first row by 1 to the left
	tmp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = tmp;

	// second row by 2
	tmp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = tmp;
	tmp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = tmp;

	// third row by 3
	tmp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = tmp;
}

void RijndaelBlock::MixColumns()
{
	unsigned char tmp[4][Nb];

	// each column is left multiplied in galois field by a special matrix 
	// each multiplication is performed by a pre-calculated lookup table
	for (size_t i = 0; i < Nb; i++) {
		tmp[0][i] = (unsigned char)(Mul2[state[0][i]] ^ Mul3[state[1][i]] ^ state[2][i] ^ state[3][i]);
		tmp[1][i] = (unsigned char)(state[0][i] ^ Mul2[state[1][i]] ^ Mul3[state[2][i]] ^ state[3][i]);
		tmp[2][i] = (unsigned char)(state[0][i] ^ state[1][i] ^ Mul2[state[2][i]] ^ Mul3[state[3][i]]);
		tmp[3][i] = (unsigned char)(Mul3[state[0][i]] ^ state[1][i] ^ state[2][i] ^ Mul2[state[3][i]]);
	}

	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < Nb; j++) {
			state[i][j] = tmp[i][j];
		}
	}
}

std::string RijndaelBlock::getEncrypted() const
{
	std::string out;
	for (const auto& it : encrypted) {
		out.push_back(it);
	}
	return out;
}