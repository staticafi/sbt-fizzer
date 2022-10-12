#include <iomodels/instrumentation_callbacks.hpp>

#include <stdbool.h>

extern "C" {
char __VERIFIER_nondet_char() {
    char n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned char __VERIFIER_nondet_uchar() {
    unsigned char n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

_Bool __VERIFIER_nondet_bool() {
    char n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    if (n > 0) {
        return true;
    }
    return false;
}

short __VERIFIER_nondet_short() {
    short n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned short __VERIFIER_nondet_ushort() {
    unsigned short n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

int __VERIFIER_nondet_int() {
    int n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned int __VERIFIER_nondet_uint() {
    unsigned int n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

long __VERIFIER_nondet_long() {
    long n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned long __VERIFIER_nondet_ulong() {
    unsigned long n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

float __VERIFIER_nondet_float() {
    float n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}

double __VERIFIER_nondet_double() {
    double n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}
}
