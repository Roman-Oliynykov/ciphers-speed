/*

Implementation of 
- Kalyna-512/512 block cipher
- Kalyna-512/512 test vectors printing
- memory block re-encryption using Kalyna-512/512 ECB mode

Authors: Olena Kachko, Roman Oliynykov

*/


#include <cstdio>

#include "k2_constants.hpp"
#include "k2_precomputed_tables.hpp"
#include "k2_512_512.hpp"
#include "../time_measure.hpp"

extern ENCRYPTED_MEMORY encrypted_memory;

K2_ROUND_KEYS_512_512 roundkey512_512 = {
		{ 0x4cd6c8f2fcc04719, 0x41e2a82d72fb56b2, 0x4f06306102bfea88, 0xc954a84cbdf2e003,   0xcffe4564be48a8, 0xf1434d1c0cde0a51, 0xdf01df63b1533d07,  0xe562f252957e3101 },
		{ 0xf2e0034f06306102, 0xbe48a8c954a84cbd, 0xde0a5100cffe4564, 0x533d07f1434d1c0c, 0x7e3101df01df63b1, 0xc04719e562f25295, 0xfb56b24cd6c8f2fc,  0xbfea8841e2a82d72 },
		{ 0x74932a31faf20824, 0x577cbc063c7700a3, 0x79d8e1ec36a169e3, 0xb8f54903a3a2dfc2, 0x5c03ab0117d25c23, 0x33e28d0ff31bbf23, 0x2701f84dc93af8e0,  0x560dda078a4bbe03 },
		{ 0xa2dfc279d8e1ec36, 0xd25c23b8f54903a3, 0x1bbf235c03ab0117, 0x3af8e033e28d0ff3, 0x4bbe032701f84dc9, 0xf20824560dda078a, 0x7700a374932a31fa,  0xa169e3577cbc063c },
		{ 0xfd8b7ca96739dfb8, 0xb4ee6851ecec4d5c, 0xd67ad9802d56ee0b, 0x5d4d08cd9c659809, 0xfa7abf00f04134c3, 0xde676df931e4ebee, 0xaab0f8ff5b5ae0a0,  0x23ea917a85c9389a },
		{ 0x659809d67ad9802d, 0x4134c35d4d08cd9c, 0xe4ebeefa7abf00f0, 0x5ae0a0de676df931, 0xc9389aaab0f8ff5b, 0x39dfb823ea917a85, 0xec4d5cfd8b7ca967,  0x56ee0bb4ee6851ec },
		{ 0xc35aa0aa7726b67a, 0x8083a01c8694f95b, 0xfc514382fb518605, 0xeb829f22ddb584d6, 0xee980666fdcdcf3a, 0x68687d092dc622b9, 0xeae660692c517503,  0xa3db59c1a7534a97 },
		{ 0xb584d6fc514382fb, 0xcdcf3aeb829f22dd, 0xc622b9ee980666fd, 0x51750368687d092d, 0x534a97eae660692c, 0x26b67aa3db59c1a7, 0x94f95bc35aa0aa77,  0x5186058083a01c86 },
		{ 0x103e37223289410b, 0xa6aaec2ae52c8553, 0x1f77d287bbd46ad5,  0x776bab4b29efeb7,  0x2f8e93197dbf039, 0xe1600093bde121e8, 0xc74340d83a2538fc,  0x826285a59a6afe8f },
		{ 0x9efeb71f77d287bb, 0xdbf0390776bab4b2, 0xe121e802f8e93197, 0x2538fce1600093bd, 0x6afe8fc74340d83a, 0x89410b826285a59a, 0x2c8553103e372232,  0xd46ad5a6aaec2ae5 },
		{ 0xbb81978c95f753b2, 0xfaa4b29431927fc9, 0x9ce3d2e3410195f3, 0xfffd0a8b6c84d727, 0x411545e3a1ede010, 0xf109c4ccd7e54458,  0x841d72804b308af,  0x52ee1289743913ae },
		{ 0x84d7279ce3d2e341, 0xede010fffd0a8b6c, 0xe54458411545e3a1, 0xb308aff109c4ccd7, 0x3913ae0841d72804, 0xf753b252ee128974, 0x927fc9bb81978c95,   0x195f3faa4b29431 },
		{ 0xc63b22ecb9873b9c, 0xdaa76f3b15a4f15b, 0x5f37eafc2ab7b962, 0x4f2957486c65cd34, 0x270fb88847c00106, 0x10b781fbe17e9dc1, 0x107f4466bd617fcf,   0x421e3630eda4ce3 },
		{ 0x65cd345f37eafc2a, 0xc001064f2957486c, 0x7e9dc1270fb88847, 0x617fcf10b781fbe1, 0xda4ce3107f4466bd, 0x873b9c0421e3630e, 0xa4f15bc63b22ecb9,  0xb7b962daa76f3b15 },
		{ 0x94e6b336e687e039, 0x4ecfddb4ac4e749c, 0x49d5312765953c60, 0x9550d9f100520ce7, 0xf9565b674e404eb0, 0x382c51f74ac4be3c, 0x308cbcfbde3d1a8e,  0xf42bb1fddc3bdefa },
		{ 0x520ce749d5312765, 0x404eb09550d9f100, 0xc4be3cf9565b674e, 0x3d1a8e382c51f74a, 0x3bdefa308cbcfbde, 0x87e039f42bb1fddc, 0x4e749c94e6b336e6,  0x953c604ecfddb4ac },
		{ 0xc8fbe43f1b0dfce0, 0x96cb2b11b53dac7f, 0xccc1853f593ef2d8,  0x54ddc23aad2d945, 0x8b1f34c308eb6f6c, 0x43592b9bf8e27aaf, 0xb81b28039f109e54,  0x2e01e4c101d21eb9 },
		{ 0xd2d945ccc1853f59, 0xeb6f6c054ddc23aa, 0xe27aaf8b1f34c308, 0x109e5443592b9bf8, 0xd21eb9b81b28039f,  0xdfce02e01e4c101, 0x3dac7fc8fbe43f1b,  0x3ef2d896cb2b11b5 },
		{ 0x91d0099e98d97a83, 0x57a083d8a45e2eab, 0xdb3302c97514a86e, 0x5ae82297303752bd, 0x4a67418b202851a3, 0xa8c451812f286790, 0x7da3e7b3bcbd5a68,  0x246ba8adb6ba6218 }
};



#define My_add_key_nb8(key, state)		\
		{										\
	state[0] += key[0];					\
	state[1] += key[1];					\
	state[2] += key[2];					\
	state[3] += key[3];					\
	state[4] += key[4];					\
	state[5] += key[5];					\
	state[6] += key[6];					\
	state[7] += key[7];					\
		}										\

inline void  My_round_nb8_enc_and_xor(K2_DATA_512 in, K2_DATA_512 out, DSTUCIPHER_KEY_8 key)
{
	out [0] = (key)[0] ^ k_s_box_mds_subst[0][((uint8_t*)in) [0 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [7 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [6 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [5 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [4 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [3 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[2 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [1 * 8 + 7]];
	out [1] = (key)[1] ^ k_s_box_mds_subst[0][((uint8_t*)in) [1 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [0 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [7 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [6 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [5 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [4 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[3 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [2 * 8 + 7]];
	out [2] = (key)[2] ^ k_s_box_mds_subst[0][((uint8_t*)in) [2 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [1 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [0 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [7 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [6 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [5 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[4 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [3 * 8 + 7]];
	out [3] = (key)[3] ^ k_s_box_mds_subst[0][((uint8_t*)in) [3 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [2 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [1 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [0 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [7 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [6 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[5 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [4 * 8 + 7]];
	out [4] = (key)[4] ^ k_s_box_mds_subst[0][((uint8_t*)in) [4 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [3 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [2 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [1 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [0 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [7 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[6 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [5 * 8 + 7]];
	out [5] = (key)[5] ^ k_s_box_mds_subst[0][((uint8_t*)in) [5 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [4 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [3 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [2 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [1 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [0 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[7 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [6 * 8 + 7]];
	out [6] = (key)[6] ^ k_s_box_mds_subst[0][((uint8_t*)in) [6 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [5 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [4 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [3 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [2 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [1 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[0 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [7 * 8 + 7]];
	out [7] = (key)[7] ^ k_s_box_mds_subst[0][((uint8_t*)in) [7 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [6 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [5 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [4 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [3 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [2 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[1 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [0 * 8 + 7]];
}

inline void  My_round_nb8_enc_and_add(K2_DATA_512 in, K2_DATA_512 out, DSTUCIPHER_KEY_8 key)
{
	out [0] = (key)[0] + (k_s_box_mds_subst[0][((uint8_t*)in) [0 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [7 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [6 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [5 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [4 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [3 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[2 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [1 * 8 + 7]]);
	out [1] = (key)[1] + (k_s_box_mds_subst[0][((uint8_t*)in) [1 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [0 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [7 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [6 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [5 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [4 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[3 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [2 * 8 + 7]]);
	out [2] = (key)[2] + (k_s_box_mds_subst[0][((uint8_t*)in) [2 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [1 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [0 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [7 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [6 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [5 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[4 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [3 * 8 + 7]]);
	out [3] = (key)[3] + (k_s_box_mds_subst[0][((uint8_t*)in) [3 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [2 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [1 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [0 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [7 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [6 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[5 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [4 * 8 + 7]]);
	out [4] = (key)[4] + (k_s_box_mds_subst[0][((uint8_t*)in) [4 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [3 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [2 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [1 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [0 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [7 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[6 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [5 * 8 + 7]]);
	out [5] = (key)[5] + (k_s_box_mds_subst[0][((uint8_t*)in) [5 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [4 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [3 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [2 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [1 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [0 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[7 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [6 * 8 + 7]]);
	out [6] = (key)[6] + (k_s_box_mds_subst[0][((uint8_t*)in) [6 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [5 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [4 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [3 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [2 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [1 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[0 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [7 * 8 + 7]]);
	out [7] = (key)[7] + (k_s_box_mds_subst[0][((uint8_t*)in) [7 * 8 + 0]]^
			k_s_box_mds_subst[1][((uint8_t*)in) [6 * 8 + 1]]	^
			k_s_box_mds_subst[2][((uint8_t*)in) [5 * 8 + 2]]	^
			k_s_box_mds_subst[3][((uint8_t*)in) [4 * 8 + 3]]	^
			k_s_box_mds_subst[4][((uint8_t*)in) [3 * 8 + 4]]	^
			k_s_box_mds_subst[5][((uint8_t*)in) [2 * 8 + 5]]	^
			k_s_box_mds_subst[6][((uint8_t*)in)	[1 * 8 + 6]]	^
			k_s_box_mds_subst[7][((uint8_t*)in) [0 * 8 + 7]]);
}



void K2_512_512_encrypt_block( K2_DATA_512 OutputBlock, K2_ROUND_KEYS_512_512 round_keys)
{
	UINT64 temp[ Nb_512 ];
	PUINT64 prkCur = (PUINT64)&round_keys[ 0 ][ 0 ];

	My_add_key_nb8(prkCur, OutputBlock);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(temp, OutputBlock, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_xor(OutputBlock, temp, prkCur);
	prkCur += 8;

	My_round_nb8_enc_and_add(temp, OutputBlock, prkCur);
}


void Test_K2_512_512_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_512; ii++)
		{
			K2_512_512_encrypt_block( encrypted_memory.block512[ ii ], roundkey512_512 );
		}
}


void print_k2_512_512_test()
{
	unsigned long long  pt88 [Nb_512] = {0x4746454443424140ULL, 0x4f4e4d4c4b4a4948ULL, 0x5756555453525150ULL,
			0x5f5e5d5c5b5a5958ULL, 0x6766656463626160ULL, 0x6f6e6d6c6b6a6968ULL,
			0x7776757473727170ULL, 0x7f7e7d7c7b7a7978ULL};
	unsigned char *text = (unsigned char *)pt88;

	printf("Kalyna-512/512:  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < Nb_512 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");

	K2_512_512_encrypt_block( pt88, roundkey512_512 );

	printf("ciphertext: ");
	for(size_t i = 0; i < Nb_512 * 8; i++)
		printf("%3x", text[i]);

	printf("\n");
}


