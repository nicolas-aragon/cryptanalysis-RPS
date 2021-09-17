#include "rps.h"
#include "fips202.h"

/**
 * Implementation of H
 * 
 * H is implemented as follows :
 * - w, s, m, h and inv_h are converted to a long uint8_t array
 * - This array is hashed into a 32 bytes string
 * - This string is used to seed a seedexpander
 * - The seedexpander is used to sample c
 */
void hash_function(rbc_67_qre c, rbc_67_qre w, rbc_67_qre s, uint8_t message[128], rbc_67_qre h, rbc_67_qre inv_h) {
	/**** Init ****/
	AES_XOF_struct* seedexpander;
	seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	uint8_t seed[SEEDEXPANDER_SEED_BYTES];
	uint8_t messageToHash[128 + 4 * 496] = {0};
	uint8_t hash[SHA512_BYTES] = {0};

	rbc_67_vspace C;
	rbc_67_vspace_init(&C, 1);
	/**************/

	memcpy(messageToHash, message, 128);
	rbc_67_qre_to_string(messageToHash + 128, s);
	rbc_67_qre_to_string(messageToHash + 128 + 496, w);
	rbc_67_qre_to_string(messageToHash + 128 + 2 * 496, h);
	rbc_67_qre_to_string(messageToHash + 128 + 3 * 496, inv_h);

	sha3_512(hash, messageToHash, 128 + 4 * 496);
	memcpy(seed, hash, 40);
	seedexpander_init(seedexpander, seed, seed + 32, SEEDEXPANDER_MAX_LENGTH);

	rbc_67_vspace_set_random_full_rank(seedexpander, C, 1);
	rbc_67_qre_set_random_from_support(seedexpander, c, C, 1);

	/**** Clear ****/
	rbc_67_vspace_clear(C);

	free(seedexpander);
}

void keygen(rbc_67_qre x, rbc_67_qre y, rbc_67_qre h, rbc_67_qre inv_h, rbc_67_vspace X, rbc_67_vspace Y) {
	/**** Init ****/
	AES_XOF_struct* seedexpander;
	seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	uint8_t seed[SEEDEXPANDER_SEED_BYTES];
	randombytes(seed, SEEDEXPANDER_SEED_BYTES);

	rbc_67_qre tmp;

	rbc_67_qre_init(&tmp);
	/**************/

	seedexpander_init(seedexpander, seed, seed + 32, SEEDEXPANDER_MAX_LENGTH);
	rbc_67_vspace_set_random_full_rank(seedexpander, X, W_X);
	rbc_67_vspace_set_random_full_rank(seedexpander, Y, W_Y);

	rbc_67_qre_set_random_from_support(seedexpander, x, X, W_X);
	rbc_67_qre_set_random_from_support(seedexpander, y, Y, W_Y);

	rbc_67_qre_inv(tmp, x);
	rbc_67_qre_mul(h, tmp, y);
	rbc_67_qre_inv(inv_h, h);

	/**** Clear ****/
	rbc_67_qre_clear(tmp);

	free(seedexpander);
}

void sign(uint8_t message[128], rbc_67_qre h, rbc_67_qre inv_h, rbc_67_qre x, rbc_67_qre y, rbc_67_qre c, rbc_67_qre a, rbc_67_qre b, rbc_67_qre s, rbc_67_vspace U) {
	/**** Init ****/
	AES_XOF_struct* seedexpander;
	seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	uint8_t seed[SEEDEXPANDER_SEED_BYTES];
	randombytes(seed, SEEDEXPANDER_SEED_BYTES);
	seedexpander_init(seedexpander, seed, seed + 32, SEEDEXPANDER_MAX_LENGTH);

	rbc_67_vspace E, F, V;
	rbc_67_qre e, f, u, v, w, tmp;

	rbc_67_vspace_init(&E, W_E);
	rbc_67_vspace_init(&F, W_F);
	rbc_67_vspace_init(&V, W_V);

	rbc_67_qre_init(&e);
	rbc_67_qre_init(&f);
	rbc_67_qre_init(&u);
	rbc_67_qre_init(&v);
	rbc_67_qre_init(&w);
	rbc_67_qre_init(&tmp);
	/**************/

	rbc_67_vspace_set_random_full_rank(seedexpander, E, W_E);
	rbc_67_vspace_set_random_full_rank(seedexpander, F, W_F);
	rbc_67_vspace_set_random_full_rank(seedexpander, U, W_U);
	rbc_67_vspace_set_random_full_rank(seedexpander, V, W_V);

	rbc_67_qre_set_random_from_support(seedexpander, e, E, W_E);
	rbc_67_qre_set_random_from_support(seedexpander, f, F, W_F);
	rbc_67_qre_set_random_from_support(seedexpander, u, U, W_U);
	rbc_67_qre_set_random_from_support(seedexpander, v, V, W_V);

	//Compute s as ey + fx.
	rbc_67_qre_mul(s, e, y);
	rbc_67_qre_mul(tmp, f, x);
	rbc_67_qre_add(s, s, tmp);

	//Compute w as uy + vx
	rbc_67_qre_mul(w, u, y);
	rbc_67_qre_mul(tmp, v, x);
	rbc_67_qre_add(w, w, tmp);

	//Compute c
	hash_function(c, w, s, message, h, inv_h);

	//Compute a = (u + ce)x
	rbc_67_qre_mul(tmp, c, e);
	rbc_67_qre_add(tmp, tmp, u);
	rbc_67_qre_mul(a, tmp, x);

	//Compute b = (v + cf)y
	rbc_67_qre_mul(tmp, c, f);
	rbc_67_qre_add(tmp, tmp, v);
	rbc_67_qre_mul(b, tmp, y);

	/**** Clear ****/
	rbc_67_vspace_clear(E);
	rbc_67_vspace_clear(F);
	rbc_67_vspace_clear(V);

	rbc_67_qre_clear(e);
	rbc_67_qre_clear(f);
	rbc_67_qre_clear(u);
	rbc_67_qre_clear(v);
	rbc_67_qre_clear(w);
	rbc_67_qre_clear(tmp);

	free(seedexpander);
}

int verify(uint8_t message[128], rbc_67_qre c, rbc_67_qre a, rbc_67_qre b, rbc_67_qre s, rbc_67_qre h, rbc_67_qre inv_h) {
	/**** Init ****/
	rbc_67_qre w, tmp, c_prime;

	int rank;

	rbc_67_qre_init(&w);
	rbc_67_qre_init(&tmp);
	rbc_67_qre_init(&c_prime);
	/**************/

	int high_rank = 59;
	int ret_value = 0;

	//Check rank(a) and rank(ah)
	rank = rbc_67_vec_get_rank_vartime(a->v, 59);
	if(rank != (W_U + W_E) * W_X) ret_value = 1;
	rbc_67_qre_mul(tmp, a, h);
	rank = rbc_67_vec_get_rank_vartime(tmp->v, 59);
	if(rank != (W_U + W_E) * W_Y) ret_value = 1;

	//Check rank(b) and rank(bh)
	rank = rbc_67_vec_get_rank_vartime(b->v, 59);
	if(rank != (W_V + W_F) * W_Y) ret_value = 1;
	rbc_67_qre_mul(tmp, b, inv_h);
	rank = rbc_67_vec_get_rank_vartime(tmp->v, 59);
	if(rank != (W_V + W_F) * W_X) ret_value = 1;

	//Check rank(s), rank(sh) and rank(sh^-1)
	rank = rbc_67_vec_get_rank_vartime(s->v, 59);
	if(rank != W_E * W_Y + W_F * W_X) ret_value = 1;
	rbc_67_qre_mul(tmp, s, h);
	rank = rbc_67_vec_get_rank_vartime(tmp->v, 59);
	if(rank != high_rank) ret_value = 1;
	rbc_67_qre_mul(tmp, s, inv_h);
	rank = rbc_67_vec_get_rank_vartime(tmp->v, 59);
	if(rank != high_rank) ret_value = 1;

	if(ret_value == 0) {
		//Compute w = ah + bh^-1 + cs
		rbc_67_qre_mul(w, a, h);
		rbc_67_qre_mul(tmp, b, inv_h);
		rbc_67_qre_add(w, w, tmp);
		rbc_67_qre_mul(tmp, c, s);
		rbc_67_qre_add(w, w, tmp);

		//Compute c'
		hash_function(c_prime, w, s, message, h, inv_h);

		if(!rbc_67_qre_is_equal_to(c_prime, c)) ret_value=1;
	}

	/**** Clear ****/
	rbc_67_qre_clear(w);
	rbc_67_qre_clear(tmp);
	rbc_67_qre_clear(c_prime);
	
	return ret_value;
}