extern int __VERIFIER_nondet_int();

int main()
{
    int x, y;
    x = __VERIFIER_nondet_int();
    y = __VERIFIER_nondet_int();

    // represents: if (x < 0 || x > 3 || y < 0 || y > 23) return 0; else return 1;
    if (x < 0)
        return 0;
    if (x > 3)
        return 0;
    if (y < 0)
        return 0;
    if (y > 23)
        return 0;
    return 1;
}
