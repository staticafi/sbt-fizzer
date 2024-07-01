typedef unsigned int size_t;
extern void *malloc (size_t __size);
extern int __VERIFIER_nondet_int(void);

int main()
{
    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);

    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);
    malloc(250ULL * 1024ULL * 1024ULL);

    if (__VERIFIER_nondet_int() == 1)
        return 1;

    return 0;
}

