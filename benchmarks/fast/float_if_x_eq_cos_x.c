#include <math.h>
extern float __VERIFIER_nondet_float();

int main()
{
    float x;
    x = __VERIFIER_nondet_float();
    if (x == (float)cos(x))
        return 1;
    return 0;
}
