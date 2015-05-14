#ifndef TIME_MEASURE
#define TIME_MEASURE


/* Block size constant definition for 64, 128, 256 and 512 bits */

const int Nb_64  = 1;
const int Nb_128 = 2;
const int Nb_256 = 4;
const int Nb_512 = 8;


// memory block for encryptions in RAM, in megabytes
const unsigned int memory_amount_for_encryption = 1024;

// encryption of 1 GB is too fast for measure; re-encrypt several times
const unsigned int number_of_reencryptions_in_memory = 8;

const unsigned int number_of_blocks_in_memory_64  = memory_amount_for_encryption * 1024 * 1024 / 8 / 1;
const unsigned int number_of_blocks_in_memory_128 = memory_amount_for_encryption * 1024 * 1024 / 8 / Nb_128;
const unsigned int number_of_blocks_in_memory_256 = memory_amount_for_encryption * 1024 * 1024 / 8 / Nb_256;
const unsigned int number_of_blocks_in_memory_512 = memory_amount_for_encryption * 1024 * 1024 / 8 / Nb_512;


/* types for data blocks */

typedef unsigned long long DATA_64;
typedef unsigned long long DATA_128[ Nb_128 ];
typedef unsigned long long DATA_256[ Nb_256 ];
typedef unsigned long long DATA_512[ Nb_512 ];


typedef union {
	DATA_64  block64 [ number_of_blocks_in_memory_64  ];
	DATA_128 block128[ number_of_blocks_in_memory_128 ];
	DATA_256 block256[ number_of_blocks_in_memory_256 ];
	DATA_512 block512[ number_of_blocks_in_memory_512 ];
} ENCRYPTED_MEMORY;


// Getting current processor number of ticks for time of call
void DetermineTime(struct timeval& ticks );

double CalculateEncryptionSpeedMemory(struct timeval& start_ticks, struct timeval& finish_ticks );

// fill memory with different constants
void InitMemoryEncryptionBlock();

#endif
