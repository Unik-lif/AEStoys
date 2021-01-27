#ifndef AES_ROUND_C
#define AES_ROUND_C

/*  This file includes AES_Round function                      *
 *	1. OneFullRound:				                           *
 *     Execute a full round for encrytion.                     *
 *  2. FinalRound:                                             *
 *     Deliberately seperated for the last round encrytion.    *
 *  3. Rv_FinalRound:                                          *
 *     Reverse operations for FinalRound.                      *
 *  4. Rv_OneFullRound:                                        *
 *     Reverse operations for OneFullRound.                    *
 *  5. KeyExpand:                                              *
 *     The key used here should be expand beforehand.          *
 *  6. KeySelect:                                              *
 *     Select the key pairs need for a loop.                   *
 *  7. Rijdael:                                                *
 *     Combine the OneFullRound and FinalRound together.       *
 *  8. Rv_RijDael:                                             *
 *     Combine the Rv_OneFullRound and Rv_FinalRound together. *
 * ----------------------------------------------------------- */
#include "aes.h"
#include "AES_Process.c"
#include "Base_change.c"


static void OneFullRound(uint8_t in[], uint8_t key[])
{
	int i;

	for(i = 0; i < Nb * Width; i++)
	{
		temp[i] = in[i];
	}
/* Since the whole input length is below or equal to Nb * Width              *
 * That's trully a very small number, so we simply count all the output here *
 * from in[0] to in[15] , enjoy yourself                                     */
	
	in[0]  = T02_Quick[s_box[temp[0]]]   ^ T03_Quick[s_box[temp[5]]] ^
	         T01_Quick[s_box[temp[10]]]  ^ T01_Quick[s_box[temp[15]]];
	in[1]  = T02_Quick[s_box[temp[1]]]   ^ T03_Quick[s_box[temp[6]]] ^
	         T01_Quick[s_box[temp[11]]]  ^ T01_Quick[s_box[temp[12]]];
	in[2]  = T02_Quick[s_box[temp[2]]]   ^ T03_Quick[s_box[temp[7]]] ^
	         T01_Quick[s_box[temp[8]]]   ^ T01_Quick[s_box[temp[13]]];
	in[3]  = T02_Quick[s_box[temp[3]]]   ^ T03_Quick[s_box[temp[4]]] ^
	         T01_Quick[s_box[temp[9]]]   ^ T01_Quick[s_box[temp[14]]];
	
	in[4]  = T01_Quick[s_box[temp[0]]]   ^ T02_Quick[s_box[temp[5]]] ^
	         T03_Quick[s_box[temp[10]]]  ^ T01_Quick[s_box[temp[15]]];
	in[5]  = T01_Quick[s_box[temp[1]]]   ^ T02_Quick[s_box[temp[6]]] ^
	         T03_Quick[s_box[temp[11]]]  ^ T01_Quick[s_box[temp[12]]];
	in[6]  = T01_Quick[s_box[temp[2]]]   ^ T02_Quick[s_box[temp[7]]] ^
	         T03_Quick[s_box[temp[8]]]   ^ T01_Quick[s_box[temp[13]]];
	in[7]  = T01_Quick[s_box[temp[3]]]   ^ T02_Quick[s_box[temp[4]]] ^
	         T03_Quick[s_box[temp[9]]]   ^ T01_Quick[s_box[temp[14]]];
	
	in[8]  = T01_Quick[s_box[temp[0]]]   ^ T01_Quick[s_box[temp[5]]] ^
	         T02_Quick[s_box[temp[10]]]  ^ T03_Quick[s_box[temp[15]]];
	in[9]  = T01_Quick[s_box[temp[1]]]   ^ T01_Quick[s_box[temp[6]]] ^
	         T02_Quick[s_box[temp[11]]]  ^ T03_Quick[s_box[temp[12]]];
	in[10] = T01_Quick[s_box[temp[2]]]   ^ T01_Quick[s_box[temp[7]]] ^
	         T02_Quick[s_box[temp[8]]]   ^ T03_Quick[s_box[temp[13]]];
	in[11] = T01_Quick[s_box[temp[3]]]   ^ T01_Quick[s_box[temp[4]]] ^
	         T02_Quick[s_box[temp[9]]]   ^ T03_Quick[s_box[temp[14]]];
	
	in[12] = T03_Quick[s_box[temp[0]]]   ^ T01_Quick[s_box[temp[5]]] ^
	         T01_Quick[s_box[temp[10]]]  ^ T02_Quick[s_box[temp[15]]];
	in[13] = T03_Quick[s_box[temp[1]]]   ^ T01_Quick[s_box[temp[6]]] ^
	         T01_Quick[s_box[temp[11]]]  ^ T02_Quick[s_box[temp[12]]];
	in[14] = T03_Quick[s_box[temp[2]]]   ^ T01_Quick[s_box[temp[7]]] ^
	         T01_Quick[s_box[temp[8]]]   ^ T02_Quick[s_box[temp[13]]];
	in[15] = T03_Quick[s_box[temp[3]]]   ^ T01_Quick[s_box[temp[4]]] ^
	         T01_Quick[s_box[temp[9]]]   ^ T02_Quick[s_box[temp[14]]];

	AddRoundKey(in, key, Nb * Width);
	memset(temp, 0, sizeof(temp));
}

static void FinalRound(uint8_t in[], uint8_t key[])
{
	int i;

	for(i = 0; i < Nb * Width; i++)
	{
		temp[i] = in[i];
	}

	in[0]  = s_box[temp[0]];
	in[1]  = s_box[temp[1]];
	in[2]  = s_box[temp[2]];
	in[3]  = s_box[temp[3]];

	in[4]  = s_box[temp[5]];
	in[5]  = s_box[temp[6]];
	in[6]  = s_box[temp[7]];
	in[7]  = s_box[temp[4]];

	in[8]  = s_box[temp[10]];
	in[9]  = s_box[temp[11]];
	in[10] = s_box[temp[8]];
	in[11] = s_box[temp[9]];

	in[12] = s_box[temp[15]];
    in[13] = s_box[temp[12]];
    in[14] = s_box[temp[13]];
    in[15] = s_box[temp[14]];
	AddRoundKey(in, key, Nb * Width);
	memset(temp, 0, sizeof(temp));
}

static void Rv_FinalRound(uint8_t in[], uint8_t key[])
{
	AddRoundKey(in, key, Nb * Width);
	
	int i;

	for(i = 0; i < Nb * Width; i++)
	{
		temp[i] = in[i];
	}

	in[0]  = inv_s_box[temp[0]];
	in[1]  = inv_s_box[temp[1]];
	in[2]  = inv_s_box[temp[2]];
	in[3]  = inv_s_box[temp[3]];

	in[4]  = inv_s_box[temp[7]];
	in[5]  = inv_s_box[temp[4]];
	in[6]  = inv_s_box[temp[5]];
	in[7]  = inv_s_box[temp[6]];

	in[8]  = inv_s_box[temp[10]];
	in[9]  = inv_s_box[temp[11]];
	in[10] = inv_s_box[temp[8]];
	in[11] = inv_s_box[temp[9]];

	in[12] = inv_s_box[temp[13]];
    in[13] = inv_s_box[temp[14]];
    in[14] = inv_s_box[temp[15]];
    in[15] = inv_s_box[temp[12]];

    memset(temp, 0, sizeof(temp));
}

static void Rv_OneFullRound(uint8_t in[], uint8_t key[])
{
	AddRoundKey(in, key, Nb * Width);

	int i;

	for(i = 0; i < Nb * Width; i++)
	{
		temp[i] = in[i];
	}

	in[0] =  inv_s_box[T0E_Quick[temp[0]]  ^ T0B_Quick[temp[4]] ^
			 		   T0D_Quick[temp[8]]  ^ T09_Quick[temp[12]]];
	in[1] =  inv_s_box[T0E_Quick[temp[1]]  ^ T0B_Quick[temp[5]] ^
			 		   T0D_Quick[temp[9]]  ^ T09_Quick[temp[13]]];
	in[2] =  inv_s_box[T0E_Quick[temp[2]]  ^ T0B_Quick[temp[6]] ^
			 		   T0D_Quick[temp[10]] ^ T09_Quick[temp[14]]];
	in[3] =  inv_s_box[T0E_Quick[temp[3]]  ^ T0B_Quick[temp[7]] ^
			           T0D_Quick[temp[11]] ^ T09_Quick[temp[15]]];

	in[4] =  inv_s_box[T09_Quick[temp[3]]  ^ T0E_Quick[temp[7]] ^
			 		   T0B_Quick[temp[11]] ^ T0D_Quick[temp[15]]];
	in[5] =  inv_s_box[T09_Quick[temp[0]]  ^ T0E_Quick[temp[4]] ^
			 		   T0B_Quick[temp[8]]  ^ T0D_Quick[temp[12]]];
	in[6] =  inv_s_box[T09_Quick[temp[1]]  ^ T0E_Quick[temp[5]] ^
			 		   T0B_Quick[temp[9]]  ^ T0D_Quick[temp[13]]];
	in[7] =  inv_s_box[T09_Quick[temp[2]]  ^ T0E_Quick[temp[6]] ^
			           T0B_Quick[temp[10]] ^ T0D_Quick[temp[14]]];

	in[8] =  inv_s_box[T0D_Quick[temp[2]]  ^ T09_Quick[temp[6]] ^
			           T0E_Quick[temp[10]] ^ T0B_Quick[temp[14]]];
	in[9] =  inv_s_box[T0D_Quick[temp[3]]  ^ T09_Quick[temp[7]] ^
			           T0E_Quick[temp[11]] ^ T0B_Quick[temp[15]]];
	in[10] = inv_s_box[T0D_Quick[temp[0]]  ^ T09_Quick[temp[4]] ^
			 	       T0E_Quick[temp[8]]  ^ T0B_Quick[temp[12]]];
	in[11] = inv_s_box[T0D_Quick[temp[1]]  ^ T09_Quick[temp[5]] ^
			 		   T0E_Quick[temp[9]]  ^ T0B_Quick[temp[13]]];

	in[12] = inv_s_box[T0B_Quick[temp[1]]  ^ T0D_Quick[temp[5]] ^
			 		   T09_Quick[temp[9]]  ^ T0E_Quick[temp[13]]];
	in[13] = inv_s_box[T0B_Quick[temp[2]]  ^ T0D_Quick[temp[6]] ^
			           T09_Quick[temp[10]] ^ T0E_Quick[temp[14]]];
	in[14] = inv_s_box[T0B_Quick[temp[3]]  ^ T0D_Quick[temp[7]] ^
			 	       T09_Quick[temp[11]] ^ T0E_Quick[temp[15]]];
	in[15] = inv_s_box[T0B_Quick[temp[0]]  ^ T0D_Quick[temp[4]] ^
			 		   T09_Quick[temp[8]]  ^ T0E_Quick[temp[12]]];

	memset(temp, 0, sizeof(temp));
}

static void KeyExpand(uint8_t key[], uint8_t exp_key[][MaxLen])
{
	uint8_t i, j;
	uint8_t temp[MaxLen] = {0};
	for(i = 0; i < Nk; i++)
		for(j = 0; j < 4; j++)
			exp_key[i][j] = key[4 * i + j];
	
	for(i = Nk; i < Nb * (Nr + 1); i++)
	{
		memcpy(temp, exp_key[i - 1], Width);
		if(i % Nk == 0)
		{	
			uint8_t Rcon[] = {RC_Store[i / Nk], 0x00, 0x00, 0x00};
			RotByte(temp);
			Array_MTA(temp, Rcon, temp, Width);
			ByteSub(temp, Width);
		}
		Array_MTA(exp_key[i - Nk], temp, exp_key[i], Width);
		memset(temp, 0, sizeof(temp));  
	}
}

static void Key_Select(uint8_t i, uint8_t sel_key[], uint8_t exp_key[][MaxLen])
{
	uint8_t k;
	for(k = 0; k < Width * Nk; k++)
	{
		sel_key[k] = exp_key[Width * i + k / Width][k % Width];
	}
}

static void Rijndael(uint8_t in[])
{
	int rd;
	Key_Select(0, sel_key, exp_key);
	AddRoundKey(in, sel_key, Nk * Width);
	memset(sel_key, 0, sizeof(sel_key));
	for(rd = 1; rd < Nr; rd++)
	{
		Key_Select(rd, sel_key, exp_key);
		OneFullRound(in, sel_key);
		memset(sel_key, 0, sizeof(sel_key));
	}
	Key_Select(Nr, sel_key, exp_key);
	FinalRound(in, sel_key);
	return ;
}

static void Rv_Rijndael(uint8_t in[])
{
	int rd;
	Key_Select(Nr, sel_key, exp_key);
	Rv_FinalRound(in, sel_key);
	for(rd = Nr - 1; rd > 0; rd--)
	{
		Key_Select(rd, sel_key, exp_key);
		Rv_OneFullRound(in, sel_key);
	}
	Key_Select(rd, sel_key, exp_key);
	AddRoundKey(in, sel_key, Nk * Width);
}

#endif