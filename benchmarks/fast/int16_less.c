extern short __VERIFIER_nondet_short();

int main()
{
    short x, y;
    x = __VERIFIER_nondet_short();
    y = __VERIFIER_nondet_short();
    if (x < -10)
        return 1;
    if (x > -1)
        return 2;
    if (x >= y)
        return 3;
    if (x + 50 > 2*y)
        return 4;
    return 0;
}
