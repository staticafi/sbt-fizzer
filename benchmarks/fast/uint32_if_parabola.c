extern unsigned int __VERIFIER_nondet_uint();

int main()
{
    unsigned int x;
    x = __VERIFIER_nondet_uint();

// long double xxx = (long double)x;           //              1 431 655 765 == x
// long double fff = 6.0*xxx-8.0-xxx*xxx;      // -2 049 638 220 867 800 643 == fff
// unsigned int iii = 6U*x-8U-x*x;             //              3 340 530 109 == iii

    if (6U*x-8U-x*x == 0U)  // Roots are: 2 and 4.
        return 1;
    return 0;
}
