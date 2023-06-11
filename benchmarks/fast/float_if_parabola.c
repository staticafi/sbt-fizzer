extern float __VERIFIER_nondet_float();

int main()
{
    float x;
    x = __VERIFIER_nondet_float();
    if (-x*x+6.0f*x-8.0f == 0)  // Roots are: 2 and 4.
        return 1;
    return 0;
}
