# RPS Cryptanalysis

This repository contains material supporting the claims from the paper "Cryptanalysis of the Rank Preserving Signature" by Nicolas Aragon, Maxime Bros, and Philippe Gaborit, published in the [18th IMA International Conference on Cryptography and Coding](https://ima.org.uk/16366/online-event-18th-ima-international-conference-on-cryptography-and-coding/ "18th IMACC").

## Dependencies

The program requires the [Rank Based Cryptography (RBC) library](http://rbc-lib.org/ "RBC library") version >= 1.2. The include directory and the librbc.a file may be placed at the root of this repository, or in the PATH of the system.

## Compiling and running

### Leakage from the signatures

This part of our program shows that RPS signatures leak information about the support of the vector space UY. A Makefile is provided to compile:

```bash
cd signature_leak
make main
./build/main
```

Here is an example of output, showing that the program recovers a vector space containing UY:

```
Valid signature
Dimension of recovered space: 26
Dimension of the intersection with U*Y: 25
Valid signature
Dimension of recovered space: 27
Dimension of the intersection with U*Y: 25
```

Values that can be modified:

* m by changing the names of the RBC functions in main.c, rps.h and rps.c
* The dimensions of the vector spaces in the parameters.h file
* The number of iterations in each execution by changing the ITERATIONS constant in main.c

### Forgery using random vectors

This part of our program shows how much time is needed in practice to forge vectors satisfying \|z1\| = \|z1.h^-1\|. A Makefile is provided to compile:

```bash
cd random_vectors
make main
./build/main
```

Here is an example of output, showing that one vector z1 such that \|z1\| = \|z1.h^-1\| is found after 5793751 iterations on average:

```
Average tries to find 1 vectors: 5793751
```

Values that can be modified:

* m by chaging the names of the RBC functions in main.c
* The target weight of zi by changing the TARGET_WEIGHT constant in main.c
* The number of iterations in each execution by changing the ITERATIONS constant in main.c
* Looking for z1 such that \|z1\| = \|z1.h^-1\| OR looking for both z1 and z2 such that \|z1\| = \|z1.h^-1\| and \|z2\| = \|z2.h\| by changing the N_VECTORS constant in main.c