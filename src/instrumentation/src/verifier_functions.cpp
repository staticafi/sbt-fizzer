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
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::SINT8);
    return n;
}

unsigned char __VERIFIER_nondet_uchar() {
    unsigned char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::UINT8);
    return n;
}

unsigned char __VERIFIER_nondet_unsigned_char() {
    unsigned char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::UINT8);
    return n;
}

_Bool __VERIFIER_nondet_bool() {
    char n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::BOOLEAN);
    if (n > 0) {
        return true;
    }
    return false;
}

short __VERIFIER_nondet_short() {
    short n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::SINT16);
    return n;
}

unsigned short __VERIFIER_nondet_ushort() {
    unsigned short n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::UINT16);
    return n;
}

int __VERIFIER_nondet_int() {
    int n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::SINT32);
    return n;
}

unsigned int __VERIFIER_nondet_uint() {
    unsigned int n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::UINT32);
    return n;
}

long __VERIFIER_nondet_long() {
    long n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n) == 4 ? type_of_input_bits::SINT32 : type_of_input_bits::SINT64);
    return n;
}

unsigned long __VERIFIER_nondet_ulong() {
    unsigned long n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, sizeof(n) == 4 ? type_of_input_bits::UINT32 : type_of_input_bits::UINT64);
    return n;
}

float __VERIFIER_nondet_float() {
    float n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::FLOAT32);
    return n;
}

double __VERIFIER_nondet_double() {
    double n;
    sbt_fizzer_target->on_read((natural_8_bit*) &n, type_of_input_bits::FLOAT64);
    return n;
}
}
