#ifndef AES_PROCESS_C
#define AES_PROCESS_C

#include "aes.h"

/* TO UNDERSTAND THIS: READ AES pdf CAREFULLY:   *
 *    AES contain several steps                  */

static uint8_t GFM(uint8_t a, uint8_t b)
{
	uint16_t ar, br, rt;
	ar = (uint16_t)a;
	br = (uint16_t)b;
	rt = 0;
	while(ar)
	{
		if(ar & 1)
		{
			rt = rt ^ br;
		}
		br <<= 1;
		if(br >= 0x100)
		{
			br = br ^ 0x11b;
		}
		ar >>= 1;
	}
	return (uint8_t) rt;
}

static uint8_t Matx_Multi(uint8_t c[], uint8_t a[])
{
	int i;
	uint8_t ret = 0x00;
	for(i = 0; i < 4; i++)
	{
		ret = MTA(GFM(c[i], a[i]), ret);
	}
	return ret;
}

static void Array_MTA(uint8_t a[], uint8_t b[], uint8_t c[], uint8_t len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		c[i] = MTA(a[i], b[i]);
	}
}

static void RotByte(uint8_t in[])
{
	int i;
	uint8_t tmp = in[0];
	for(i = 1; i < 4; i++)
	{
		in[i - 1] = in[i];
	}
	in[3] = tmp;
}

static void ByteSub(uint8_t in[], uint8_t len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		in[i] = s_box[in[i]];
	}
}

static void Rv_ByteSub(uint8_t in[], uint8_t len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		in[i] = inv_s_box[in[i]];
	}
}

static void ShiftRow(uint8_t in[])
{
	int i, k, j;
	uint8_t tmp;
	for(i = 1; i < 4; i++)
	{
		k = 0;
		while(k < i)
		{
			tmp = in[Nb * i];
			for(j = 1; j < Nb; j++)
			{
				in[Nb * i + j - 1] = in[Nb * i + j];
			}
			in[Nb * i + Nb - 1] = tmp;
			k++;
		}
	}
}

static void Rv_ShiftRow(uint8_t in[])
{
	int i, k, j;
	uint8_t tmp;
	for(i = 1; i < 4; i++)
	{
		k = 0;
		while(k < i)
		{
			tmp = in[Nb * i + Nb - 1];
			for(j = Nb - 1; j > 0; j--)
			{
				in[Nb * i + j] = in[Nb * i + j - 1];
			}
			in[Nb * i] = tmp;
			k++;
		}
	}	
}
//FULL ATTENTION HERE! NOT SO EASY!
static void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) 
{
	d[0] = GFM(a[0], b[0]) ^ GFM(a[1], b[1]) ^ GFM(a[2], b[2]) ^ GFM(a[3], b[3]);
	d[1] = GFM(a[3], b[0]) ^ GFM(a[0], b[1]) ^ GFM(a[1], b[2]) ^ GFM(a[2], b[3]);
	d[2] = GFM(a[2], b[0]) ^ GFM(a[3], b[1]) ^ GFM(a[0], b[2]) ^ GFM(a[1], b[3]);
	d[3] = GFM(a[1], b[0]) ^ GFM(a[2], b[1]) ^ GFM(a[3], b[2]) ^ GFM(a[0], b[3]);
}

static void MixColumn(uint8_t in[])
{
	uint8_t a[] = {0x02, 0x03, 0x01, 0x01}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = in[Nb * i + j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			in[Nb * i + j] = res[i];
		}
	}
}

static void Rv_MixColumn(uint8_t in[])
{
	uint8_t a[] = {0x0e, 0x0b, 0x0d, 0x09}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = in[Nb*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			in[Nb*i+j] = res[i];
		}
	}
}

static void AddRoundKey(uint8_t in[], uint8_t key[], uint8_t len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		in[i] = MTA(in[i], key[i]);
	}
}

#endif