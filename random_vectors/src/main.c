#include <stdio.h>
#include <stdlib.h>
#include "rbc.h"

/*
 * This program demonstrates that for random vectors z1 and z2, we have |z1| = |z1.h^-1| and |z2| = |z2.h|
 * with an attainable probability for certain values of m, k, and the target weight.
 * 
 * m is fixed to 61 and k to 59.
 * 
 * The weight can be modified, 55 is the value from the RPS parameter set RPS-C1.
 */

#define TARGET_WEIGHT 55
#define ITERATIONS (1 << 1)

//Set to 1 one to look for |z1| = |z1.h^-1| and 2 to search for |z2| = |z2.h| as well
#define N_VECTORS 1

int main(void) {
	/**** Init ****/
	rbc_61_field_init();
	rbc_61_qre_init_modulus(59);

	AES_XOF_struct* seedexpander;
	seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	uint8_t seed[SEEDEXPANDER_SEED_BYTES];
	randombytes(seed, SEEDEXPANDER_SEED_BYTES);
	seedexpander_init(seedexpander, seed, seed + 32, SEEDEXPANDER_MAX_LENGTH);

	//Build h and h^-1 once
	rbc_61_vspace X, Y;
	rbc_61_qre x, y, h, inv_h, tmp;

	rbc_61_vspace_init(&X, 5);
	rbc_61_vspace_init(&Y, 5);
	rbc_61_qre_init(&x);
	rbc_61_qre_init(&y);
	rbc_61_qre_init(&h);
	rbc_61_qre_init(&inv_h);
	rbc_61_qre_init(&tmp);

	rbc_61_vspace_set_random_full_rank(seedexpander, X, 5);
	rbc_61_vspace_set_random_full_rank(seedexpander, Y, 5);

	rbc_61_qre_set_random_from_support(seedexpander, x, X, 5);
	rbc_61_qre_set_random_from_support(seedexpander, y, Y, 5);

	rbc_61_qre_inv(tmp, x);
	rbc_61_qre_mul(h, tmp, y);
	rbc_61_qre_inv(inv_h, h);

	unsigned long totalTries = 0;

	//Then we look for values such that |z1| = |z1.h^-1| (and |z2| = |z2.h| if N_VECTORS == 2)
	//We repeat this process ITERATIONS time
	for(int iter = 0 ; iter<ITERATIONS ; iter++) {
		unsigned long tries = 0;
		rbc_61_vspace suppZ1, suppZ2;
		rbc_61_qre z1, z2, prod1, prod2;

		rbc_61_qre_init(&z1);
		rbc_61_qre_init(&z2);
		rbc_61_qre_init(&prod1);
		rbc_61_qre_init(&prod2);
		rbc_61_vspace_init(&suppZ1, TARGET_WEIGHT);
		rbc_61_vspace_init(&suppZ2, TARGET_WEIGHT);

		int done = 0;
		do {
			tries++;
			//Sample new seed for seedexpander so it does not block execution
			if((tries % (1<<18)) == 0) {
				randombytes(seed, SEEDEXPANDER_SEED_BYTES);
				seedexpander_init(seedexpander, seed, seed + 32, SEEDEXPANDER_MAX_LENGTH);
			}
			//z1 and z2 must be changed, independently, at each iteration, as in the attack.
			rbc_61_vspace_set_random_full_rank(seedexpander, suppZ1, TARGET_WEIGHT);
			rbc_61_qre_set_zero(z1);
			rbc_61_qre_set_random_from_support(seedexpander, z1, suppZ1, TARGET_WEIGHT);
			rbc_61_qre_mul(prod1, z1, inv_h);
			if(N_VECTORS == 2) {
				rbc_61_vspace_set_random_full_rank(seedexpander, suppZ2, TARGET_WEIGHT);
				rbc_61_qre_set_zero(z2);
				rbc_61_qre_set_random_from_support(seedexpander, z2, suppZ2, TARGET_WEIGHT);
				rbc_61_qre_mul(prod2, z2, h);
			}

			done = 1;
			if(rbc_61_vec_get_rank(prod1->v, 59) != TARGET_WEIGHT) {
				done = 0;
			}
			if(N_VECTORS == 2) {
				if(rbc_61_vec_get_rank(prod2->v, 59) != TARGET_WEIGHT) done = 0;
			} 
		} while(!done);

		totalTries += tries;

		rbc_61_qre_clear(z1);
		rbc_61_qre_clear(z2);
		rbc_61_qre_clear(prod1);
		rbc_61_qre_clear(prod2);
		rbc_61_vspace_clear(suppZ1);
		rbc_61_vspace_clear(suppZ2);
	}

	printf("Average tries to find %d vectors: %lu\n", N_VECTORS, totalTries / ITERATIONS);
	
	rbc_61_vspace_clear(X);
	rbc_61_vspace_clear(Y);
	rbc_61_qre_clear(x);
	rbc_61_qre_clear(y);
	rbc_61_qre_clear(h);
	rbc_61_qre_clear(inv_h);
	rbc_61_qre_clear(tmp);

	rbc_61_qre_clear_modulus();
	free(seedexpander);

	return 0;
}
