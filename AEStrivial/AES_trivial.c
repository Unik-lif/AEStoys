/* aes encryption in trivial way       *
 * Author : Link                       *
 * date: 2021-1				       *
 * Tips: we assume the parameter below *
 *  Nb = 4, Nk = 4, Nr = 10            * 
 * ------------------------------------*
 *  If the plaintext is short than 16B *
 *  we composite it with (16-i)-(16-i) *
 * ------------------------------------*
 *                                     */

#include "aes.h"
#include "AES_Round.c"
#include "AES_Process.c"
#include "Base_change.c"

static void Showchar(uint8_t in[], int len)
{
	int i;
	printf("The string form:\n");
	for(i = 0; i < len; i++)
	{
		printf("%c,", in[i]);
	}
	printf("\n");
} 

int main(void)
{
	Init();
	Read_plain(in);
	Read_key(key);
	KeyExpand(key, exp_key);
	printf("Encode result:\n");
	clock_t start,end;
	start = clock();
	Rijndael(in);
	//PriArray(in, Width * Nb);
	Rv_Rijndael(in);
	end = clock();
	printf("clock tick: %ld\n", end - start);
	printf("Decode result:\n");
	PriArray(in, Width * Nb);
	Showchar(in, Width * Nb);
}