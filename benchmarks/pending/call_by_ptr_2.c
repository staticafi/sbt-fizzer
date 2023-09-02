typedef long unsigned int size_t;
typedef int (*__compar_fn_t) (const void *, const void *);
extern void qsort (void *__base, size_t __nmemb, size_t __size, __compar_fn_t __compar) __attribute__ ((__nonnull__ (1, 4)));

extern char __VERIFIER_nondet_char();
extern char __VERIFIER_nondet_int();

int my_cmp(const void *left, const void *right)
{
    return *(char const*)left < *(char const*)right;
}

int main()
{
    char arr[10] = { 0,1,2,3,4,5,6,7,8,9 };
    int n = __VERIFIER_nondet_int();
    if (n < 1 || n > 10)
        return -2;
    qsort(arr, n, 1, my_cmp);
    return (n == 5) ? -1 : 0;
}
