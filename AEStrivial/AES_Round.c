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
	ByteSub(in, Nb * Width);
	ShiftRow(in);
	MixColumn(in);
	AddRoundKey(in, key, Nb * Width);
}

static void FinalRound(uint8_t in[], uint8_t key[])
{
	ByteSub(in, Nb * Width);
	ShiftRow(in);
	AddRoundKey(in, key, Nb * Width);
}

static void Rv_FinalRound(uint8_t in[], uint8_t key[])
{
	AddRoundKey(in, key, Nb * Width);
	Rv_ShiftRow(in);
	Rv_ByteSub(in, Nb * Width);
}

static void Rv_OneFullRound(uint8_t in[], uint8_t key[])
{
	AddRoundKey(in, key, Nb * Width);
	Rv_MixColumn(in);
	Rv_ShiftRow(in);
	Rv_ByteSub(in, Nb * Width);
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