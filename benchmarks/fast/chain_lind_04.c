extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();

    // solution:  x0 = 1, x1 = 1;

    if (1.133*x0 + 5.281*x1 - 6.414 == 0.0)
    if (24.14*x0 - 1.210*x1 - 22.93 == 0.0)
        return 1;

    return 0;
}
