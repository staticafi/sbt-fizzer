#include <instrumentation/fuzz_target.hpp>
#include <utility/config.hpp>
#if COMPILER() == COMPILER_VC()
#   define _Bool bool
#else
#   include <stdbool.h>
#endif

using namespace instrumentation;

extern "C" {
char __VERIFIER_nondet_char() {
    char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned char __VERIFIER_nondet_uchar() {
    unsigned char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned char __VERIFIER_nondet_unsigned_char() {
    unsigned char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

_Bool __VERIFIER_nondet_bool() {
    char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    if (n > 0) {
        return true;
    }
    return false;
}

short __VERIFIER_nondet_short() {
    short n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned short __VERIFIER_nondet_ushort() {
    unsigned short n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

int __VERIFIER_nondet_int() {
    int n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned int __VERIFIER_nondet_uint() {
    unsigned int n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

long __VERIFIER_nondet_long() {
    long n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

unsigned long __VERIFIER_nondet_ulong() {
    unsigned long n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

float __VERIFIER_nondet_float() {
    float n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}

double __VERIFIER_nondet_double() {
    double n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n));
    return n;
}
}
