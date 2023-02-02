#include <stdbool.h>

extern short __VERIFIER_nondet_short();

int main()
{
    short x1, y1, x2, y2;
    bool cond_1, cond_2;
    x1 = __VERIFIER_nondet_short();
    y1 = __VERIFIER_nondet_short();
    x2 = __VERIFIER_nondet_short();
    y2 = __VERIFIER_nondet_short();

    if (x1 == y1 + 123)
        cond_1 = true;
    else
        cond_1 = false;

    if (x2 != y2 + 123)
        cond_2 = true;
    else
        cond_2 = false;

    if (cond_1 == true)
        if (cond_2 == true)
            return 1;

    return 0;
}
