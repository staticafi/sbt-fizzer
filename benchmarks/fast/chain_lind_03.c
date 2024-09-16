extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();

    // solution:  x0 = 0.8, x1 = 0.6;

    if (  x0 + 2*x1 - 2 == 0.0)
    if (2*x0 + 3*x1 - 3.4 == 0.0)
        return 1;

    return 0;
}
