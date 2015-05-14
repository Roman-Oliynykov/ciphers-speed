// This file contains implementation of BelT Algorithm
// with 256 bit key length
// Copyright 2011 PlainText.SU




#include <cstdio>
#include <iostream>

#include "Belt.hpp"
#include "../time_measure.hpp"

#define __int8 char
#define __int32 int


#define RotHi(x, r)		(((x) << (r)) | ((x) >> (32 - (r))))

#define U1(x)	( (x) >> 24 ) 
#define U2(x)	(((x) >> 16 ) & 0xff )
#define U3(x)	(((x) >> 8  ) & 0xff )
#define U4(x)	( (x) & 0xff )

#define HU1(x,H)	(((unsigned __int32) (H)[ U1((x)) ]) << 24)
#define HU2(x,H)	(((unsigned __int32) (H)[ U2((x)) ]) << 16)
#define HU3(x,H)	(((unsigned __int32) (H)[ U3((x)) ]) <<  8)
#define HU4(x,H)	(((unsigned __int32) (H)[ U4((x)) ]))

#define G(x,H,r)	RotHi(HU4((x),(H)) | HU3((x),(H)) | HU2((x),(H)) | HU1((x),(H)),(r))
#define SWAP(x,y,tmp)	(tmp) = (x); (x) = (y); (y) = (tmp);
//#define SWAP(x,y,tmp)	swap((x), (y));

unsigned __int8 H[256] = 
{
	0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
	0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
	0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
	0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
	0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
	0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
	0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
	0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
	0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
	0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
	0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
	0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
	0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
	0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
	0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21, 
	0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D
};

unsigned int KeyIndex[8][7] = 
{
	{ 0, 1, 2, 3, 4, 5, 6 },
	{ 7, 0, 1, 2, 3, 4, 5 },
	{ 6, 7, 0, 1, 2, 3, 4 },
	{ 5, 6, 7, 0, 1, 2, 3 }, 
	{ 4, 5, 6, 7, 0, 1, 2 }, 
	{ 3, 4, 5, 6, 7, 0, 1 },
	{ 2, 3, 4, 5, 6, 7, 0 },
	{ 1, 2, 3, 4, 5, 6, 7 }
};

void belt_init(unsigned __int8 * k, int kLen,unsigned __int8* ks)
{
	unsigned int i;
	switch(kLen)
	{
	//128 ���
	case 16: 
		for(i = 0; i<4; ++i)
		{
			((unsigned __int32 *)ks)[i] = ((unsigned __int32 *)k)[i];
			((unsigned __int32 *)ks)[i+4] = ((unsigned __int32 *)k)[i];
		}
		
		break;
	//192 ����
	case 24:
		for(i = 0; i<6; ++i)
		{
			((unsigned __int32 *)ks)[i] = ((unsigned __int32 *)k)[i];
		}
		((unsigned __int32 *)ks)[6] = (((unsigned __int32 *)k)[0]) ^ (((unsigned __int32 *)k)[1]) ^ (((unsigned __int32 *)k)[2]);
		((unsigned __int32 *)ks)[7] = (((unsigned __int32 *)k)[3]) ^ (((unsigned __int32 *)k)[4]) ^ (((unsigned __int32 *)k)[5]);
		break;
	//256 ���
	case 32:
		for(i = 0; i<32; ++i) ks[i] = k[i];
		break;
	}	
}

void belt_encrypt(unsigned __int8 * Block, unsigned __int8 *ks)
{
	unsigned __int32 a = ((unsigned __int32 *)Block)[0];
	unsigned __int32 b = ((unsigned __int32 *)Block)[1];
	unsigned __int32 c = ((unsigned __int32 *)Block)[2];
	unsigned __int32 d = ((unsigned __int32 *)Block)[3];
	unsigned __int32 e;
	int i;
	unsigned __int32 tmp;
	unsigned __int32 * key = (unsigned __int32*)ks;

	for(i = 0; i<8; ++i)
	{				
		b ^= G((a + key[KeyIndex[i][0]]), H, 5); 
		c ^= G((d + key[KeyIndex[i][1]]), H, 21);
		a = (unsigned __int32)(a - G((b + key[KeyIndex[i][2]]), H, 13));
		e = (G((b + c + key[KeyIndex[i][3]]), H, 21) ^ (unsigned __int32)(i + 1));

		b += e;
		c = (unsigned __int32)(c - e);
		d += G((c + key[KeyIndex[i][4]]), H, 13);
		b ^= G((a + key[KeyIndex[i][5]]), H, 21);
		c ^= G((d + key[KeyIndex[i][6]]), H, 5);
		SWAP(a, b, tmp);
		SWAP(c, d, tmp);
		SWAP(b, c, tmp);
	}

	((unsigned __int32 *)Block)[0] = b;
	((unsigned __int32 *)Block)[1] = d;
	((unsigned __int32 *)Block)[2] = a;
	((unsigned __int32 *)Block)[3] = c;
}

void swapbytes(unsigned int& z) {
	z = ( (z >> 24) & 0xFF ) | ( ( (z >> 16) & 0xFF ) << 8 ) |  \
			(( (z >> 8 ) & 0xFF ) << 16 ) | ( ( (z >> 0) & 0xFF ) << 24 );
}

unsigned int bt_block[] = { 0xB194BAC8, 0x0A08F53B, 0x366D008E, 0x584A5DE4 };
unsigned int bt_key[] = {	0xE9DEE72C, 0x8F0C0FA6, 0x2DDB49F4, 0x6F739647,
						0x06075316, 0xED247A37, 0x39CBA383, 0x03A98BF6 };


void print_BelT_test() {

	for(unsigned int i = 0; i < sizeof(bt_block)/sizeof(bt_block[0]); i++)
		swapbytes( bt_block[ i ] );
	for(unsigned int i = 0; i < sizeof(bt_key)/sizeof(bt_key[0]); i++)
		swapbytes( bt_key[ i ] );

	unsigned char *text = (unsigned char *)bt_block;

	printf("STB 34.101.31-2011(BelT):  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < 16; i++)
		printf("%3x", text[i]);
	printf("\n");

	belt_encrypt( (unsigned __int8 *) text, (unsigned __int8 *)bt_key);

	printf("ciphertext: ");
	for(size_t i = 0; i < 16; i++)
		printf("%3x", text[i]);
	printf("\n");
}

extern ENCRYPTED_MEMORY encrypted_memory;

void Test_BelT_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_128; ii++)
		{
			belt_encrypt( (unsigned __int8 *)encrypted_memory.block128[ ii ], (unsigned __int8 *)bt_key );
		}
}

