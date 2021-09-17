#ifndef RPS_H
#define RPS_H

#include "rbc.h"
#include "parameters.h"

void keygen(rbc_67_qre x, rbc_67_qre y, rbc_67_qre h, rbc_67_qre inv_h, rbc_67_vspace X, rbc_67_vspace Y);
void sign(uint8_t message[128], rbc_67_qre h, rbc_67_qre inv_h, rbc_67_qre x, rbc_67_qre y, rbc_67_qre c, rbc_67_qre a, rbc_67_qre b, rbc_67_qre s, rbc_67_vspace U);
int verify(uint8_t message[128], rbc_67_qre c, rbc_67_qre a, rbc_67_qre b, rbc_67_qre s, rbc_67_qre h, rbc_67_qre inv_h);

#endif