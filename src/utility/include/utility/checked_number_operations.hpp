#ifndef UTILITY_CHECKED_NUMBER_OPERATIONS_HPP_INCLUDED
#   define UTILITY_CHECKED_NUMBER_OPERATIONS_HPP_INCLUDED

#   include <utility/assumptions.hpp>
#   include <utility/basic_numeric_types.hpp>

natural_8_bit checked_add_8_bit(natural_8_bit const a, natural_8_bit const b);
natural_8_bit checked_mul_8_bit(natural_8_bit const a, natural_8_bit const b);

natural_16_bit checked_add_16_bit(natural_16_bit const a, natural_16_bit const b);
natural_16_bit checked_mul_16_bit(natural_16_bit const a, natural_16_bit const b);

natural_32_bit checked_add_32_bit(natural_32_bit const a, natural_32_bit const b);
natural_32_bit checked_mul_32_bit(natural_32_bit const a, natural_32_bit const b);

natural_64_bit checked_add_64_bit(natural_64_bit const a, natural_64_bit const b);
natural_64_bit checked_mul_64_bit(natural_64_bit const a, natural_64_bit const b);

#endif
