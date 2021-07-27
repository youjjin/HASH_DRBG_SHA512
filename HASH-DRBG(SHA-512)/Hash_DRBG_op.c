#include "HASH-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>

void Instantiaite_Function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	int len = entropy_len + nonce_len + personalization_len;
	unsigned char input_string[250] = { 0x00, };
	unsigned char temp[112] = { 0x00, };
	int i;

	memcpy(input_string, entropy, entropy_len);
	memcpy(input_string + entropy_len, nonce, nonce_len);
	memcpy(input_string + entropy_len + nonce_len, personalization, personalization_len);

	//Hash_df_op(input_string, len, state->state_handle.V);
	int new_len = 5 + len;
	unsigned char temp1[250] = { 0x00, };
	unsigned char temp2[250] = { 0x00, };
	unsigned char N[4] = { 0x00, 0x00, 0x03, 0x78 };
	unsigned char H[64] = { 0x00, };
	unsigned char H1[64] = { 0x00, };
	unsigned char seed[128] = { 0x00, };

	//try1
	temp1[0] = 0x01;
	temp1[1] = 0x00;
	temp1[2] = 0x00;
	temp1[3] = 0x03;
	temp1[4] = 0x78;
	memcpy(temp1 + 5,input_string, len);
	SHA512_Enc_op(temp1, new_len, H);
	memcpy(seed, H, 64);
	//try2
	temp2[0] = 0x02;
	temp2[1] = 0x00;
	temp2[2] = 0x00;
	temp2[3] = 0x03;
	temp2[4] = 0x78;
	memcpy(temp2 + 5, input_string, len);
	SHA512_Enc_op(temp2, new_len, H1);
	memcpy(seed + 64, H1, 64);

	memcpy(state->state_handle.V, seed, 111);
	/*****************************************************/

	temp[0] = 0x00;
	memcpy(temp + 1, state->state_handle.V, 111);

	//Hash_df_op(temp, 112, state->state_handle.C);
	//try1
	temp1[0] = 0x01;
	temp1[1] = 0x00;
	temp1[2] = 0x00;
	temp1[3] = 0x03;
	temp1[4] = 0x78;
	memcpy(temp1 + 5, temp, 112);
	SHA512_Enc_op(temp1, 117, H);
	memcpy(seed, H, 64);
	//try2
	temp2[0] = 0x02;
	temp2[1] = 0x00;
	temp2[2] = 0x00;
	temp2[3] = 0x03;
	temp2[4] = 0x78;
	memcpy(temp2 + 5, temp, 112);
	SHA512_Enc_op(temp2, 117, H1);
	memcpy(seed + 64, H1, 64);

	memcpy(state->state_handle.C, seed, 111);
	/*****************************************************/

	state->state_handle.reseed_counter = 1;

}

void Reseed_Function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	int len = 112 + entropy_len + additional_len;
	unsigned char seed[250] = { 0x00, };
	unsigned char tmp[112] = { 0x00, };
	int i;

	seed[0] = 0x01;
	memcpy(seed + 1, state->state_handle.V, 111);
	memcpy(seed + 112, entropy, 111);
	memcpy(seed + 112, entropy, entropy_len);
	memcpy(seed + 112 + entropy_len, additional, additional_len);

//	Hash_df_op(seed, len, state->state_handle.V);
	int new_len = 5 + len;
	unsigned char temp[250] = { 0x00, };
	unsigned char temp1[250] = { 0x00, };
	unsigned char N[4] = { 0x00, 0x00, 0x03, 0x78 };
	unsigned char H[64] = { 0x00, };
	unsigned char H1[64] = { 0x00, };
	unsigned char seed_out[128] = { 0x00, };

	//try1
	temp[0] = 0x01;
	temp[1] = 0x00;
	temp[2] = 0x00;
	temp[3] = 0x03;
	temp[4] = 0x78;
	memcpy(temp + 5, seed, len);
	SHA512_Enc_op(temp, new_len, H);
	memcpy(seed_out, H, 64);
	//try2
	temp1[0] = 0x02;
	temp1[1] = 0x00;
	temp1[2] = 0x00;
	temp1[3] = 0x03;
	temp1[4] = 0x78;
	memcpy(temp1 + 5, seed, len);
	SHA512_Enc_op(temp1, new_len, H1);
	memcpy(seed_out + 64, H1, 64);

	memcpy(state->state_handle.V, seed_out, 111);
	/**********************************************/

	tmp[0] = 0x00;
	memcpy(tmp + 1, state->state_handle.V, 111);

	//Hash_df_op(tmp, 112, state->state_handle.C);
	//try1
	temp[0] = 0x01;
	temp[1] = 0x00;
	temp[2] = 0x00;
	temp[3] = 0x03;
	temp[4] = 0x78;
	memcpy(temp + 5, tmp, 112);
	SHA512_Enc_op(temp, 117, H);
	memcpy(seed_out, H, 64);
	//try2
	temp1[0] = 0x02;
	temp1[1] = 0x00;
	temp1[2] = 0x00;
	temp1[3] = 0x03;
	temp1[4] = 0x78;
	memcpy(temp1 + 5, tmp, 112);
	SHA512_Enc_op(temp1, 117, H1);
	memcpy(seed_out + 64, H1, 64);

	memcpy(state->state_handle.C, seed_out, 111);
	/************************************************/
	state->state_handle.reseed_counter = 1;
}

void SUM_of_2_111_op(unsigned char* input1, unsigned int len1, unsigned char* input2, unsigned int len2, unsigned char* output)
{
	unsigned int sum = 0;
	unsigned char carry = 0x00;
	int j = 0;

	unsigned int len = 111;
	unsigned char string1[111] = { 0x00, };
	unsigned char string2[111] = { 0x00, };
	memcpy(string1 + (len - len1), input1, len1);
	memcpy(string2 + (len - len2), input2, len2);

	int i = len - 1;
	while (i >= 0)
	{
		sum = string1[i] + string2[i] + carry;
		if (sum > 0xff)
			carry = 0x01;
		else
			carry = 0x00;
		output[i] = sum & 0xff;

		i--;
	}

}

void Generate_Function_Yes_op(STATE* state, unsigned char* entropy, unsigned int entropylen, unsigned char* additional, unsigned int additionallen, unsigned char* output)
{
	int i;
	int len = 112 + entropylen + additionallen;
	unsigned char seed[250] = { 0x00, };
	unsigned char random[256] = { 0x00, };
	unsigned char H[64] = { 0x00, };
	unsigned char temp[112] = { 0x00, };
	unsigned char temp1[111] = { 0x00, };
	unsigned char temp2[111] = { 0x00, };
	unsigned char counter[4] = { state->state_handle.reseed_counter & 0xff000000, state->state_handle.reseed_counter & 0x00ff0000, state->state_handle.reseed_counter & 0x0000ff00, state->state_handle.reseed_counter & 0x00000ff };

	/*reseed*/
	Reseed_Function_op(state, entropy, entropylen, additional, additionallen);

	/*hash*/
	//Hash_Gen_op(state, random);
	unsigned char V[111] = { 0x00, };
	unsigned char tmp[64] = { 0x00, };
	unsigned char out[256] = { 0x00, };
	unsigned char one = 0x01;
	memcpy(V, state->state_handle.V, 111);

	/*1*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*2*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 64, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*3*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 128, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*4*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 192, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	memcpy(output, out, 256);

	/*undate V & reseed_counter*/
	temp[0] = 0x03;
	for (i = 1; i < 112; i++)
		temp[i] = state->state_handle.V[i - 1];

	SHA512_Enc_op(temp, 112, H);

	SUM_of_2_111_op(state->state_handle.C, 111, H, 64, temp1);
	SUM_of_2_111_op(temp1, 111, counter, 4, temp2);
	SUM_of_2_111_op(temp2, 111, state->state_handle.V, 111, state->state_handle.V);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

}


void Generate_Function_No_op(STATE* state, unsigned char* additional, unsigned int additionallen, unsigned char* output)
{
	int len1 = 112 + additionallen;
	unsigned char seed1[250] = { 0x00, };
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
		memcpy(seed1 + 1, state->state_handle.V, 111);
		memcpy(seed1 + 112, additional, additionallen);
		SHA512_Enc_op(seed1, len1, hash);
		SUM_of_2_111_op(V, 111, hash, 64, state->state_handle.V);
	}

	//Hash_Gen_op(state, random);
	unsigned char tmp[64] = { 0x00, };
	unsigned char out[256] = { 0x00, };
	unsigned char one = 0x01;
	memcpy(V, state->state_handle.V, 111);

	/*1*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*2*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 64, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*3*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 128, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	/*4*/
	SHA512_Enc_op(V, 111, tmp);
	memcpy(out + 192, tmp, 64);
	SUM_of_2_111_op(V, 111, &one, 1, V);
	memcpy(output, out, 256);

	/**************************************/
	memcpy(output, random, 256);
	memcpy(V, state->state_handle.V, 111);
	memcpy(C, state->state_handle.C, 111);

	temp[0] = 0x03;
	memcpy(temp + 1, state->state_handle.V, 111);
	SHA512_Enc_op(temp, 112, H);

	SUM_of_2_111_op(C, 111, H, 64, temp1);
	SUM_of_2_111_op(temp1, 111, counter, 4, temp2);
	SUM_of_2_111_op(temp2, 111, V, 111, state->state_handle.V);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

}


void Hash_DRBG_SHA512_yes_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropy_input1, unsigned int entropy_input1_len, unsigned char* entropy_input2, unsigned int entropy_input2_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization_string, unsigned int personalization_string_len, unsigned char* additional_input1, unsigned int additional_input1_len, unsigned char* additional_input2, unsigned int additional_input2_len, unsigned char* returned_bits)
{
	unsigned char pseudorandom_bits1[256] = { 0x00, };
	unsigned char pseudorandom_bits2[256] = { 0x00, };

	Instantiaite_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization_string, personalization_string_len);

	if (state->state_control.prediction_resistance_flag == 1) //예측내성 지원
	{
		Generate_Function_Yes_op(state, entropy_input1, entropy_input1_len, additional_input1, additional_input1_len, pseudorandom_bits1);
		Generate_Function_Yes_op(state, entropy_input2, entropy_input2_len, additional_input2, additional_input2_len, pseudorandom_bits2);
	}

	memcpy(returned_bits, pseudorandom_bits2, 256);
}

void Hash_DRBG_SHA512_no_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* nonce, unsigned int nonce_len, unsigned char*  personalization_string, unsigned int personalization_string_len, unsigned char* additional_input1, unsigned int additional_input1_len, unsigned char* additional_input2, unsigned int additional_input2_len, unsigned char* returned_bits)
{
	unsigned char pseudorandom_bits1[256] = { 0x00, };
	unsigned char pseudorandom_bits2[256] = { 0x00, };

	Instantiaite_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization_string, personalization_string_len);
	Reseed_Function_op(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);
	if (state->state_control.prediction_resistance_flag == 0) //예측내성 미지원
	{
		Generate_Function_No_op(state, additional_input1, additional_input1_len, pseudorandom_bits1);
		Generate_Function_No_op(state, additional_input2, additional_input2_len, pseudorandom_bits2);
	}

	memcpy(returned_bits, pseudorandom_bits2, 256);
}