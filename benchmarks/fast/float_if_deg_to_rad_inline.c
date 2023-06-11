extern float __VERIFIER_nondet_float();

#define PI 3.1415f
#define torad(a) (PI * ((a) / 180.0f))
#define abs(a) ((a) < 0.0f ? -(a) : (a))
#define feq(a,b, eps) (abs((a) - (b)) < (eps))

int main()
{
    if (feq(torad(__VERIFIER_nondet_float()), PI / 2.0f, 0.001f))
        return 1;
    return 0;
}
