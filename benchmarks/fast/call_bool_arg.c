extern int __VERIFIER_nondet_int();
extern void abort();

void foo(int cond)
{
    if (!cond)
        abort();
}

int main()
{
    int x;
    x = __VERIFIER_nondet_int();
    foo(x < 123);
    return 0;
}
