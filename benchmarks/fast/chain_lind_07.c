extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();
    double x2 = __VERIFIER_nondet_double();

    // a solution:  x0 = 1.034155145432722023, x1 = 0.3561034302884813485, x2 = 0.6739642216646661854;

    if (  x0 - 0.95*x1 - 4*x2 + 2 == 0.0)
    if (2*x0 - 3.00*x1        - 1 == 0.0)
        return 1;

    return 0;
}
