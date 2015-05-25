#Ciphers-speed

Encryption speed comparison of 64-bit Linux optimized software implementation of block ciphers (ECB mode, several times reencryption of 1 GB RAM block with different data): 
- Kalyna (Ukrainian national standard DSTU 7624:2014), all variants of block and key length; 
- AES (FIPS-197), 128 and 256 key length;
- GOST 28147-89;
- BelT (Belarussian standard STB 34.101.31-2011);
- Kuznyechik (128-bit block cipher from the draft standard of Russia).


##Examples of comparison results

###Ubuntu Linux, gcc version 4.9.2, Intel Core i5-4670@3.40GHz

Kalyna-128/128      2611.77 Mbit/s
Kalyna-128/256      1779.52 Mbit/s
Kalyna-256/256      2017.97 Mbit/s
Kalyna-256/512      1560.89 Mbit/s
Kalyna-512/512      1386.46 Mbit/s
AES-128             2525.89 Mbit/s
AES-256             1993.53 Mbit/s
GOST 28147-89       639.18 Mbit/s
STB 34.101.31-2011  1055.92 Mbit/s
Kuznyechik          1081.08 Mbit/s


###iMac13.2, Intel Core i7

Kalyna-128/128      1788.88 Mbit/s
Kalyna-128/256      1236.32 Mbit/s
Kalyna-256/256      1315.4 Mbit/s
Kalyna-256/512      1023.76 Mbit/s
Kalyna-512/512      1177.91 Mbit/s
AES-128             1645.97 Mbit/s
AES-256             1189.04 Mbit/s
GOST 28147-89       569.475 Mbit/s
STB 34.101.31-2011  936.657 Mbit/s
Kuznyechik          1158.67 Mbit/s

