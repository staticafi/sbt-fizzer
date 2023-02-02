extern char __VERIFIER_nondet_char();

int main()
{
    char  data[4];
    data[0] = __VERIFIER_nondet_char();
    data[1] = __VERIFIER_nondet_char();
    data[2] = __VERIFIER_nondet_char();
    data[3] = __VERIFIER_nondet_char();

    if (data[0] == 'b')
        if (data[1] == 'a')
            if (data[2] == 'd')
                if (data[3] == '!')
                    return 1;
    return 0;
}
