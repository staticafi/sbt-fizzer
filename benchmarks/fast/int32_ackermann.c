extern int __VERIFIER_nondet_int();


static int  ackermann(int const  x, int const  y)
{
    if (x == 0)
        return y + 1;
    if (y == 0)
        return ackermann(x - 1,1);
    return ackermann(x - 1,ackermann(x,y - 1));
}


int main()
{
    int x, y;
    x = __VERIFIER_nondet_int();
    y = __VERIFIER_nondet_int();

    // represents: if (x < 0 || x > 3 || y < 0 || y > 23) return 0;
    if (x < 0)
        return 0;
    if (x > 3)
        return 0;
    if (y < 0)
        return 0;
    if (y > 23)
        return 0;

    int r = ackermann(x,y);

    // represents: if (x < 2 || r >= 4) return 1;
    if (x < 2)
        return 1;
    if (r >= 4)
        return 1;

    return 2;
}
