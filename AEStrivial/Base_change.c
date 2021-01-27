#ifndef BASE_CHANGE_C
#define BASE_CHANGE_C

#include "aes.h"

/* Some Basic function for AES.      *
 * Read_plain: Read the plaintext.   *
 * Read_key: Read the key info       *
 * Pri_Array: print the result out   */

static void Init(void)
{
	memset(exp_key, 0, sizeof(exp_key));
	memset(sel_key, 0, sizeof(sel_key));
	memset(in     , 0, sizeof(exp_key));
	memset(key    , 0, sizeof(sel_key));
}

static void Read_plain(uint8_t in[])
{
	int i;
	int len;
	char buf[MaxStr];
	memset(buf, 0, sizeof(buf));
	FILE *fp;
	fp = fopen("/home/linka/HW/CA/plaintxt.txt", "r");
	fgets(buf, 17, fp);
	len = strlen(buf);
	printf("buf:%s\n", buf);
	for(i = 0; i < len; i++)
	{
		in[i] = buf[i];
	}
	if(len < 16)
	{
		for(i = len - 1; i < 16; i++)
		{
			in[i] = 16 - len;
		}
	}
	printf("in:%s\n", in);
	fclose(fp);
}

static void Read_key(uint8_t key[])
{
	int i;
	int len;
	char buf[MaxStr];
	memset(buf, 0, sizeof(buf));
	FILE *fp;
	fp = fopen("/home/linka/HW/CA/key.txt", "r");
	fgets(buf, 17, fp);
	len = strlen(buf);
	printf("buf = %s\n", buf);
	for(i = 0; i < len; i++)
	{
		key[i] = buf[i];
	}
	printf("key = %s\n", key);
	fclose(fp);
} 

static void PriArray(uint8_t in[], uint8_t len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		printf("0x%2x,",in[i]);
	}
	printf("\n");
}

#endif