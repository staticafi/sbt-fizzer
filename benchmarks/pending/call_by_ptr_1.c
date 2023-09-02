extern char __VERIFIER_nondet_char(void);

char foo(char x)
{
    return x == 'A' ? 'a' : 'X';
}

char bar(char x)
{
    return x == 'B' ? 'b' : 'Y';
}

int main()
{
    char c = __VERIFIER_nondet_char();
    char x = __VERIFIER_nondet_char();
    char (*fn[2])(char) = { &foo, &bar };
    char y;
    if (c < 0 || c > 1)
        return -1;
    y = fn[c](x);
    return y == 'a';
}