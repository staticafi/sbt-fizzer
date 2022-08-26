#include <utility/checked_number_operations.hpp>

natural_8_bit checked_add_8_bit(natural_8_bit const a, natural_8_bit const b)
{
    natural_8_bit const sum = a + b;
    ASSUMPTION(sum >= a);
    return sum;
}

natural_8_bit checked_mul_8_bit(natural_8_bit const a, natural_8_bit const b)
{
    natural_8_bit const mul = a * b;
    ASSUMPTION(b == natural_8_bit(0U) || a == (mul / b));
    return mul;
}

natural_16_bit checked_add_16_bit(natural_16_bit const a, natural_16_bit const b)
{
    natural_16_bit const sum = a + b;
    ASSUMPTION(sum >= a);
    return sum;
}

natural_16_bit checked_mul_16_bit(natural_16_bit const a, natural_16_bit const b)
{
    natural_16_bit const mul = a * b;
    ASSUMPTION(b == natural_16_bit(0U) || a == (mul / b));
    return mul;
}

natural_32_bit checked_add_32_bit(natural_32_bit const a, natural_32_bit const b)
{
    natural_32_bit const sum = a + b;
    ASSUMPTION(sum >= a);
    return sum;
}

natural_32_bit checked_mul_32_bit(natural_32_bit const a, natural_32_bit const b)
{
    natural_32_bit const mul = a * b;
    ASSUMPTION(b == natural_32_bit(0U) || a == (mul / b));
    return mul;
}

natural_64_bit checked_add_64_bit(natural_64_bit const a, natural_64_bit const b)
{
    natural_64_bit const sum = a + b;
    ASSUMPTION(sum >= a);
    return sum;
}

natural_64_bit checked_mul_64_bit(natural_64_bit const a, natural_64_bit const b)
{
    natural_64_bit const mul = a * b;
    ASSUMPTION(b == natural_64_bit(0U) || a == (mul / b));
    return mul;
}
