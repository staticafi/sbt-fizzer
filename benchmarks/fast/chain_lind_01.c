extern double __VERIFIER_nondet_double(void);

int main() {
    double x1 = __VERIFIER_nondet_double();
    double x2 = __VERIFIER_nondet_double();
    double x3 = __VERIFIER_nondet_double();

    if (x1 - x2 == 0.0)
    if (x1 - 10.0 >= 0.0)
    if (x1 + x2 + x3 == 0.0)
        return 1;

    return 0;
}
