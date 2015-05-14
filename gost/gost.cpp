#include <cstdio>

#include "../time_measure.hpp"
#include "gost.hpp"

GOST28147_COMPRESSED_SBOX CompressedSBox = {0xE4, 0xBA, 0x49, 0xC2, 0x6D, 0xD8, 0xF0, 0xAE,
											 0x26, 0x3B, 0x81, 0x1C, 0x07, 0x7F, 0x55, 0x93,
											 0x75, 0xD8, 0xA1, 0x1D, 0x0A, 0x83, 0x94, 0xF2,
											 0xEE, 0x4F, 0x6C, 0xC7, 0xB6, 0x20, 0x59, 0x3B,
											 0x46, 0xBC, 0xA7, 0x01, 0x75, 0x2F, 0x1D, 0xD8,
											 0x34, 0x6A, 0x89, 0x5E, 0x90, 0xC3, 0xFB, 0xE2,
											 0x1D, 0xFB, 0xD4, 0x01, 0x53, 0x7F, 0xA5, 0x49,
											 0x90, 0x2A, 0x3E, 0xE7, 0x66, 0xB8, 0x82, 0xCC};

VOID GOST28147DecompressSBox(PGOST28147_COMPRESSED_SBOX CompressedSBox,
			     PGOST28147_EXTENDED_SBOX	SBox);


VOID GOST28147EncryptBlocks(PGOST28147_BLOCK Block,
							PGOST28147_KEY Key);


#define GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, Cycle)			\
	BlockB ^= SBox[(((BlockA + ((PULONG)Key)[Cycle]))       & 255)      ] ^ \
		  SBox[(((BlockA + ((PULONG)Key)[Cycle]) >>  8) & 255) + 256] ^ \
		  SBox[(((BlockA + ((PULONG)Key)[Cycle]) >> 16) & 255) + 512] ^ \
		  SBox[(((BlockA + ((PULONG)Key)[Cycle]) >> 24))       + 768]

#define GOST28147EncryptBlock(BlockA, BlockB, Key, SBox)     \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 0); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 1); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 2); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 3); \
        GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 4); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 5); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 6); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 7); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 0); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 1); \
 	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 2); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 3); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 4); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 5); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 6); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 7); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 0); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 1); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 2); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 3); \
        GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 4); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 5); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 6); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 7); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 7); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 6); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 5); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 4); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 3); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 2); \
	GOST28147EncryptCycle(BlockA, BlockB, Key, SBox, 1); \
        GOST28147EncryptCycle(BlockB, BlockA, Key, SBox, 0)


#define GOST28147SBoxTransformation(SBoxA, SBoxB) (((SBoxA) <<       (SBoxB & 0x1F)) | \
						   ((SBoxA) >> (32 - (SBoxB & 0x1F))))

GOST28147_EXTENDED_SBOX SBox;

void init (void){GOST28147DecompressSBox(CompressedSBox, SBox);};

VOID GOST28147DecompressSBox(PGOST28147_COMPRESSED_SBOX CompressedSBox,
			     PGOST28147_EXTENDED_SBOX	SBox)
{
	ULONG ul = 0;
	ULONG i, j, k;

	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 16; j++)
		{
			for(k = 0; k < 16; k++)
			{
				SBox[ul] = GOST28147SBoxTransformation(((CompressedSBox[i * 16 + j] & 0xF0) |
									(CompressedSBox[i * 16 + k] & 0x0F)), (i * 8 + 11));
				ul++;
			}
		}
	}
}

VOID GOST28147EncryptBlocks(PGOST28147_BLOCK Block,
			    PGOST28147_KEY	     Key)
{
	GOST28147_BLOCK Block1;

	Block1[0] = Block[0];
	Block1[1] = Block[1];

	GOST28147EncryptBlock(Block1[0], Block1[1], Key, SBox);

	Block[0] = Block1[1];
	Block[1] = Block1[0];
}

GOST28147_KEY gost_key = { 0, 1, 2, 3, 4, 5, 6, 7 };
extern ENCRYPTED_MEMORY encrypted_memory;

void Test_GOST_Speed_Expanded_Memory()
{
	unsigned long long tricky_compiler = 0;
	init();

	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_64; ii++)
		{
			GOST28147EncryptBlocks( (PGOST28147_BLOCK)&encrypted_memory.block64[ ii ], gost_key );
			tricky_compiler ^= encrypted_memory.block64[ ii ];
		}

	encrypted_memory.block64[ 0 ] = tricky_compiler;
}


void print_gost_test() {
	printf("GOST 28147-89:\ntest vectors depend on selected S-box set.\n");
}
