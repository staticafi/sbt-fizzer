#include <math.h>
extern float __VERIFIER_nondet_float();

int main()
{
    float x,y,z;
    x = __VERIFIER_nondet_float();
    y = __VERIFIER_nondet_float();
    z = x*x + y*y;
    if (123.25f < z && z < 123.75f)
        return 1;
    return 0;
}
