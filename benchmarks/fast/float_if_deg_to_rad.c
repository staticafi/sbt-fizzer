extern float __VERIFIER_nondet_float();

#define PI 3.1415f

int main()
{
    float deg,rad,delta,x;
    deg = __VERIFIER_nondet_float();
    rad = PI * (deg / 180.0f);
    delta = rad - PI / 2.0f;
    x = delta < 0.0f ? -delta : delta;
    if (x < 0.001f)
        return 1;
    return 0;
}
