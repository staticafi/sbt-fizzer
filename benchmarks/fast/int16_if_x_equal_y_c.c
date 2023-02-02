extern short __VERIFIER_nondet_short();

int main()
{
    short x,y;
    x = __VERIFIER_nondet_short();
    y = __VERIFIER_nondet_short();
    if (x == y - 12345)
        return 1;
    return 0;
}
