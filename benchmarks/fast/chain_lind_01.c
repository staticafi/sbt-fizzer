extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();
    double x2 = __VERIFIER_nondet_double();

    // solution: x0 = 10, x1 = 10, x2 = -20;

    if (x0 - x1 == 0.0)
    if (x0 - 10.0 >= 0.0)
    if (x0 + x1 + x2 == 0.0)
        return 1;

    return 0;
}
