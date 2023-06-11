extern float __VERIFIER_nondet_float();

int main()
{
    float x;
    x = __VERIFIER_nondet_float();
    if (1.23f*x*x-4.56f*x-7.89f == 0) // Roots:~ -1.285, 4,992
        return 1;
    return 0;
}
