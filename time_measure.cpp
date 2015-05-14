#include <sys/time.h>

#include <iostream>

using std::cerr;
using std::endl;

#include "time_measure.hpp"

ENCRYPTED_MEMORY encrypted_memory;

unsigned long long resolution_ticks;

void DetermineTime(struct timeval& ticks)
{
	gettimeofday(&ticks, NULL);
}

double CalculateEncryptionSpeedMemory(struct timeval& t1, struct timeval& t2 )
{
	double elapsedTime = 0.0; /* ms */

	elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
	elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;  // us to ms

	return number_of_reencryptions_in_memory * double( memory_amount_for_encryption ) * 1024 * 1024 * 8 / \
			elapsedTime / 1000;
}

void InitMemoryEncryptionBlock()
{
	for(unsigned int i = 0; i < number_of_blocks_in_memory_128; i++)
	{
		encrypted_memory.block128[ i ][ 0 ] = i; 
		encrypted_memory.block128[ i ][ 1 ] = i << 4;
	}
}

