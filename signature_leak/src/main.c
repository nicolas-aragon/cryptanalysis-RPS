#include <stdio.h>
#include <stdlib.h>
#include "rps.h"
#include "parameters.h"
#include "rbc.h"

#define VERBOSE 0
#define ITERATIONS 10

int main(void) {
	/**** Init ****/
	rbc_67_field_init();
	rbc_67_qre_init_modulus(59);

	for(int iter=0 ; iter<ITERATIONS ; iter++) {
		/**** Keygen ****/
		rbc_67_qre x, y, h, inv_h;
		rbc_67_vspace X, Y, U;

		rbc_67_qre_init(&x);
		rbc_67_qre_init(&y);
		rbc_67_qre_init(&h);
		rbc_67_qre_init(&inv_h);
		rbc_67_vspace_init(&X, W_X);
		rbc_67_vspace_init(&Y, W_Y);
		rbc_67_vspace_init(&U, W_U);

		keygen(x, y, h, inv_h, X, Y);

		if(VERBOSE) {
			printf("X = \n"); rbc_67_vspace_print(X, W_X); printf("\n");
			printf("Y = \n"); rbc_67_vspace_print(Y, W_Y); printf("\n");
			printf("x ="); rbc_67_qre_print(x); printf("\n");
			printf("y ="); rbc_67_qre_print(y); printf("\n");
			printf("h ="); rbc_67_qre_print(h); printf("\n");
			printf("inv_h ="); rbc_67_qre_print(inv_h); printf("\n");
		}

		/**** Signature ****/
		//For simplicity we limit ourselves to l=1

		uint8_t message[128]; //Arbitraty message
		randombytes(message, 128);

		rbc_67_qre c, a, b, s;
		rbc_67_qre_init(&c);
		rbc_67_qre_init(&a);
		rbc_67_qre_init(&b);
		rbc_67_qre_init(&s);

		//U is an output of the signature process for testing the cryptanlysis result only.
		sign(message, h, inv_h, x, y, c, a, b, s, U);

		if(VERBOSE) {
			printf("c ="); rbc_67_qre_print(c); printf("\n");
			printf("a ="); rbc_67_qre_print(a); printf("\n");
			printf("b ="); rbc_67_qre_print(b); printf("\n");
			printf("s ="); rbc_67_qre_print(s); printf("\n");
		}

		/**** Verify ****/
		int status = verify(message, c, a, b, s, h, inv_h);

		if(status) {
			printf("Invalid signature\n");
		}
		else {
			printf("Valid signature\n");

			/**** Here we demonstrate how we can recover a vector space containing the support of cey ****/
			//First we compute : w, ah and ah + cs
			rbc_67_qre w, ah, ah_cs, tmp;
			rbc_67_qre_init(&w);
			rbc_67_qre_init(&ah);
			rbc_67_qre_init(&ah_cs);
			rbc_67_qre_init(&tmp);

			int rank;

			//Compute w = ah + bh^-1 + cs
			rbc_67_qre_mul(w, a, h);
			rbc_67_qre_mul(tmp, b, inv_h);
			rbc_67_qre_add(w, w, tmp);
			rbc_67_qre_mul(tmp, c, s);
			rbc_67_qre_add(w, w, tmp);

			//Compute ah
			rbc_67_qre_mul(ah, a, h);
			rbc_67_qre_mul(ah_cs, b, inv_h);

			//Compute ah + cs
			rbc_67_qre_mul(tmp, c, s);
			rbc_67_qre_add(ah_cs, ah, tmp);

			//Intersect the 3 supports
			int dim1, dim2;
			rbc_67_vspace recovered_support, tmp_vspace;
			rbc_67_vspace_init(&recovered_support, 59);
			rbc_67_vspace_init(&tmp_vspace, 59);

			rbc_67_vspace_set(recovered_support, w->v, 59);
			dim1 = rbc_67_vec_gauss(recovered_support, 59, NULL, 0);
			rbc_67_vspace_set(tmp_vspace, ah->v, 59);
			dim2 = rbc_67_vec_gauss(tmp_vspace, 59, NULL, 0);
			dim1 = rbc_67_vspace_intersection(recovered_support, recovered_support, tmp_vspace, dim1, dim2);
			rbc_67_vspace_set(tmp_vspace, ah_cs->v, 59);
			dim2 = rbc_67_vec_gauss(tmp_vspace, 59, NULL, 0);
			dim1 = rbc_67_vspace_intersection(recovered_support, recovered_support, tmp_vspace, dim1, dim2);

			printf("Dimension of recovered space: %d\n", dim1);

			//Test intersection with uy
			rbc_67_vspace target, test;
			rbc_67_vspace_init(&target, 59);
			rbc_67_vspace_init(&test, 59);

			rbc_67_vspace_product(target, U, Y, W_U, W_Y);
			dim2 = rbc_67_vspace_intersection(test, target, recovered_support, W_U*W_Y, dim1);

			printf("Dimension of the intersection with U*Y: %d\n", dim2);

			rbc_67_qre_clear(w);
			rbc_67_qre_clear(ah);
			rbc_67_qre_clear(ah_cs);
			rbc_67_qre_clear(tmp);
			rbc_67_vspace_clear(recovered_support);
			rbc_67_vspace_clear(tmp_vspace);
			rbc_67_vspace_clear(target);
			rbc_67_vspace_clear(test);
		}

		/**** Clear ****/
		rbc_67_qre_clear(x);
		rbc_67_qre_clear(y);
		rbc_67_qre_clear(h);
		rbc_67_qre_clear(inv_h);
		rbc_67_qre_clear(c);
		rbc_67_qre_clear(a);
		rbc_67_qre_clear(b);
		rbc_67_qre_clear(s);
		rbc_67_vspace_clear(X);
		rbc_67_vspace_clear(Y);
		rbc_67_vspace_clear(U);	
	}
	
	rbc_67_qre_clear_modulus();

	return 0;
}