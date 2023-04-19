#include <stdbool.h>

extern char __VERIFIER_nondet_char();

int main()
{
    char a,b;
    bool z;
    a = __VERIFIER_nondet_char();
    b = __VERIFIER_nondet_char();
    z = (a == 12 && b == 21);
    return (int)z;
}
