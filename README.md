#Ciphers-speed

Encryption speed comparison of 64-bit Linux optimized software implementation of block ciphers (ECB mode, several times reencryption of 1 GB RAM block with different data): 
- Kalyna (Ukrainian national standard DSTU 7624:2014), all variants of block and key length; 
- AES (FIPS-197), 128 and 256 key length;
- GOST 28147-89;
- BelT (Belarussian standard STB 34.101.31-2011);
- Kuznyechik (128-bit block cipher from the draft standard of Russia).


##Examples of comparison results

###Ubuntu Linux, gcc version 4.9.2, Intel Core i5-4670 @ 3.40GHz

| Block cipher        | Performance, Mbit/s |
|---------------------|--------------------:|
| Kalyna-128/128      | 2611.77  |
| Kalyna-128/256      | 1809.70  |
| Kalyna-256/256      | 2017.97  |
| Kalyna-256/512      | 1560.89  |
| Kalyna-512/512      | 1386.46  |
| AES-128             | 2525.89  |
| AES-256             | 1993.53  |
| GOST 28147-89       | 639.18   |
| STB 34.101.31-2011  | 1188.83  |
| Kuznyechik          | 1081.08  |

###iMac13.2, Intel Core i7

| Block cipher        | Performance, Mbit/s |
|---------------------|--------------------:|
| Kalyna-128/128      | 1874.39  |
| Kalyna-128/256      | 1295.55  |
| Kalyna-256/256      | 1392.48  |
| Kalyna-256/512      | 1088.88  |
| Kalyna-512/512      | 1243.49  |
| AES-128             | 1747.09  |
| AES-256             | 1257.43  |
| GOST 28147-89       |  576.10  |
| STB 34.101.31-2011  | 1080.02  |
| Kuznyechik          | 1146.31  |


