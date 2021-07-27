#include "HASH-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>

// N = no_of_bits = 888 / len_seed = 2
void Instantiaite_Function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	int len = entropy_len + nonce_len + personalization_len;
	unsigned char* input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char temp[112] = { 0x00, };
	int i;

	for (i = 0; i < entropy_len; i++)
		input_string[i] = entropy[i];

	for (i = entropy_len; i < entropy_len + nonce_len; i++)
		input_string[i] = nonce[i - entropy_len];


	for (i = entropy_len + nonce_len; i < entropy_len + nonce_len + personalization_len; i++)
		input_string[i] = personalization[i - (entropy_len + nonce_len)];

	Hash_df(input_string, len, state->state_handle.V);

	temp[0] = 0x00;
	for (i = 1; i < 112; i++)
		temp[i] = state->state_handle.V[i - 1];

	Hash_df(temp, 112, state->state_handle.C);

	state->state_handle.reseed_counter = 1;

	free(input_string);
}

void Hash_df(unsigned char* input, unsigned int inputlen, unsigned char* output)
{
	int len = 5 + inputlen;
	unsigned char* temp = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char* temp1 = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char N[4] = { 0x00, 0x00, 0x03, 0x78 };
	unsigned char H[64] = { 0x00, };
	unsigned char H1[64] = { 0x00, };
	unsigned char seed[128] = { 0x00, };

	int i;

	//try1
	temp[0] = 0x01;
	for (i = 1; i < 5; i++)
		temp[i] = N[i - 1];

	for (i = 5; i < len; i++)
		temp[i] = input[i - 5];

	SHA512(temp, len, H);

	for (i = 0; i < 64; i++)
		seed[i] = H[i];
	//try2
	temp1[0] = 0x02;
	for (i = 1; i < 5; i++)
		temp1[i] = N[i - 1];

	for (i = 5; i < len; i++)
		temp1[i] = input[i - 5];

	SHA512(temp1, len, H1);

	for (i = 64; i < 128; i++)
		seed[i] = H1[i - 64];

	memcpy(output, seed, 111);

	free(temp);
	free(temp1);

}

void Reseed_Function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	int len = 112 + entropy_len + additional_len;
	unsigned char* seed = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char temp[112] = { 0x00, };

	int i;

	seed[0] = 0x01;

	for (i = 1; i < 112; i++)
		seed[i] = state->state_handle.V[i - 1];

	for (i = 112; i < 112 + entropy_len; i++)
		seed[i] = entropy[i - 112];

	for (i = 112 + entropy_len; i < 112 + entropy_len + additional_len; i++)
		seed[i] = additional[i - (112 + entropy_len)];

	Hash_df(seed, len, state->state_handle.V);


	temp[0] = 0x00;
	for (i = 1; i < 112; i++)
		temp[i] = state->state_handle.V[i - 1];

	Hash_df(temp, 112, state->state_handle.C);

	state->state_handle.reseed_counter = 1;

	free(seed);

}

void SUM_of_2_111(unsigned char* input1, unsigned int len1, unsigned char* input2, unsigned int len2, unsigned char* output)
{
	unsigned int len;
	unsigned int sum = 0;
	unsigned char carry = 0x00;
	int j = 0;

	if (len1 >= len2)
		len = len1;
	else
		len = len2;

	unsigned char* string1 = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char* string2 = (unsigned char*)calloc(len, sizeof(unsigned char));

	memcpy(string1 + (len - len1), input1, len1);
	memcpy(string2 + (len - len2), input2, len2);


	int i;
	for (i = len - 1; i >= 0; i--)
	{
		sum = string1[i] + string2[i] + carry;

		if (sum > 0xff)
			carry = 0x01;
		else
			carry = 0x00;

		output[i] = sum & 0xff;
	}

}

void Hash_Gen(STATE* state, unsigned char* output)
{
	unsigned char V[111] = { 0x00, };
	unsigned char temp[64] = { 0x00, };
	unsigned char out[256] = { 0x00, };	
	unsigned char one =  0x01;
	int i;
	for (i = 0; i < 111; i++)
		V[i] = state->state_handle.V[i];

	for (i = 0; i < 4; i++)
	{
		SHA512(V, 111, temp);
		memcpy(out + (64 * i), temp, 64);
		SUM_of_2_111(V, 111, &one, 1, V);
	}

	for (i = 0; i < 256; i++)
		output[i] = out[i];

}

void Generate_Function_Yes(STATE* state, unsigned char* entropy, unsigned int entropylen, unsigned char* additional, unsigned int additionallen, unsigned char* output)
{
	int len = 112 + entropylen + additionallen;
	unsigned char* seed = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char random[256] = { 0x00, };
	unsigned char V[111] = { 0x00, };
	memcpy(V, state->state_handle.V, 111);
	unsigned char C[111] = { 0x00, };
	memcpy(C, state->state_handle.C, 111);
	unsigned char H[64] = { 0x00, };
	unsigned char temp[112] = { 0x00, };
	unsigned char temp1[111] = { 0x00, };
	unsigned char temp2[111] = { 0x00, };
	unsigned char counter[4] = { state->state_handle.reseed_counter & 0xff000000, state->state_handle.reseed_counter & 0x00ff0000, state->state_handle.reseed_counter & 0x0000ff00, state->state_handle.reseed_counter & 0x00000ff };
	int i;

	Reseed_Function(state, entropy, entropylen, additional, additionallen);

	Hash_Gen(state, random);


	memcpy(output, random, 256);

	for (i = 0; i < 111; i++)
		V[i] = state->state_handle.V[i];
	for (i = 0; i < 111; i++)
		C[i] = state->state_handle.C[i];


	temp[0] = 0x03;
	for (i = 1; i < 112; i++)
		temp[i] = V[i - 1];

	SHA512(temp, 112, H);
	SUM_of_2_111(C, 111, H, 64, temp1);
	SUM_of_2_111(temp1, 111, counter, 4, temp2);
	SUM_of_2_111(temp2, 111, V, 111, state->state_handle.V);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

	free(seed);

}


void Generate_Function_No(STATE* state, unsigned char* additional, unsigned int additionallen, unsigned char* output)
{
	int len1 = 112 + additionallen;
	unsigned char* seed1 = (unsigned char*)calloc(len1, sizeof(unsigned char));
	unsigned char random[256] = { 0x00, };
	unsigned char V[111] = { 0x00, };
	memcpy(V, state->state_handle.V, 111);

	unsigned char C[111] = { 0x00, };
	memcpy(C, state->state_handle.C, 111);

	unsigned char H[64] = { 0x00, };
	unsigned char hash[64] = { 0x00, };
	unsigned char temp[112] = { 0x00, };
	unsigned char temp1[111] = { 0x00, };
	unsigned char temp2[111] = { 0x00, };
	unsigned char counter[4] = { state->state_handle.reseed_counter & 0xff000000, state->state_handle.reseed_counter & 0x00ff0000, state->state_handle.reseed_counter & 0x0000ff00, state->state_handle.reseed_counter & 0x00000ff };

	int i;

	if (additionallen != 0)
	{
		seed1[0] = 0x02;
		for (i = 1; i < 112; i++)
			seed1[i] = V[i - 1];

		for (i = 112; i < 112 + additionallen; i++)
			seed1[i] = additional[i - 112];

		SHA512(seed1, len1, hash);
		SUM_of_2_111(V, 111, hash, 64, state->state_handle.V);
	}

	Hash_Gen(state, random);

	for (i = 0; i < 256; i++)
		output[i] = random[i];

	for (i = 0; i < 111; i++)
		V[i] = state->state_handle.V[i];
	for (i = 0; i < 111; i++)
		C[i] = state->state_handle.C[i];

	temp[0] = 0x03;
	for (i = 1; i < 112; i++)
		temp[i] = V[i - 1];

	SHA512(temp, 112, H);

	SUM_of_2_111(C, 111, H, 64, temp1);
	SUM_of_2_111(temp1, 111, counter, 4, temp2);
	SUM_of_2_111(temp2, 111, V, 111, state->state_handle.V);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

	free(seed1);
}


void Hash_DRBG_SHA512_yes(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropy_input1, unsigned int entropy_input1_len, unsigned char* entropy_input2, unsigned int entropy_input2_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization_string, unsigned int personalization_string_len, unsigned char* additional_input1, unsigned int additional_input1_len, unsigned char* additional_input2, unsigned int additional_input2_len, unsigned char* returned_bits)
{
	unsigned char pseudorandom_bits1[256] = { 0x00, };
	unsigned char pseudorandom_bits2[256] = { 0x00, };

	Instantiaite_Function(state, entropy, entropy_len, nonce, nonce_len, personalization_string, personalization_string_len);

	if (state->state_control.prediction_resistance_flag == 1) //예측내성 지원
	{
		Generate_Function_Yes(state, entropy_input1, entropy_input1_len, additional_input1, additional_input1_len, pseudorandom_bits1);
		Generate_Function_Yes(state, entropy_input2, entropy_input2_len, additional_input2, additional_input2_len, pseudorandom_bits2);
	}

	memcpy(returned_bits, pseudorandom_bits2, 256);
}

void Hash_DRBG_SHA512_no(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization_string, unsigned int personalization_string_len, unsigned char* additional_input1, unsigned int additional_input1_len, unsigned char* additional_input2, unsigned int additional_input2_len, unsigned char* returned_bits)
{
	unsigned char pseudorandom_bits1[256] = { 0x00, };
	unsigned char pseudorandom_bits2[256] = { 0x00, };

	Instantiaite_Function(state, entropy, entropy_len, nonce, nonce_len, personalization_string, personalization_string_len);
	Reseed_Function(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);
	if (state->state_control.prediction_resistance_flag == 0) //예측내성 미지원
	{
		Generate_Function_No(state, additional_input1, additional_input1_len, pseudorandom_bits1);
		Generate_Function_No(state, additional_input2, additional_input2_len, pseudorandom_bits2);
	}

	memcpy(returned_bits, pseudorandom_bits2, 256);
}