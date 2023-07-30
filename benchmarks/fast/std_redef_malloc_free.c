extern int __VERIFIER_nondet_int();

static char mem[100];
static int idx = 0;
char* malloc(int n) 
{
    char* ptr;
    ptr = mem + idx;
    idx += n;
    return ptr;
}

void free(void* p)
{
    // nothing to do.
}

extern char __VERIFIER_nondet_char();

int main()
{
    char* ptr;
    int n;
    n = __VERIFIER_nondet_int();
    if (n < 1 || n > 1000) // Intentionally larger limit than maximum.
        return -1;
    ptr = malloc(n);
    free(ptr);
    return 0;
}
