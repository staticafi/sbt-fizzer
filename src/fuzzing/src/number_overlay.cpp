#include <fuzzing/number_overlay.hpp>
#include <utility/assumptions.hpp>
#include <utility/hash_combine.hpp>

namespace  fuzzing {


number_overlay  make_number_overlay(float_64_bit const  value, type_of_input_bits const  type)
{
    number_overlay  result;
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:   result._boolean = value < 0.5 ? false : true; break;
        case type_of_input_bits::UINT8:     result._uint8 = cast_float_value<natural_8_bit>(value); break;
        case type_of_input_bits::SINT8:     result._sint8 = cast_float_value<integer_8_bit>(value); break;
        case type_of_input_bits::UINT16:    result._uint16 = cast_float_value<natural_16_bit>(value); break;
        case type_of_input_bits::SINT16:    result._sint16 = cast_float_value<integer_16_bit>(value); break;
        case type_of_input_bits::UINT32:    result._uint32 = cast_float_value<natural_32_bit>(value); break;
        case type_of_input_bits::SINT32:    result._sint32 = cast_float_value<integer_32_bit>(value); break;
        case type_of_input_bits::UINT64:    result._uint64 = cast_float_value<natural_64_bit>(value); break;
        case type_of_input_bits::SINT64:    result._sint64 = cast_float_value<integer_64_bit>(value); break;
        case type_of_input_bits::FLOAT32:   result._float32 = cast_float_value<float_32_bit>(value); break;
        case type_of_input_bits::FLOAT64:   result._float64 = value; break;
        default: { UNREACHABLE(); } break;
    }
    return result;
}


bool compare(number_overlay const  v1, number_overlay const  v2, type_of_input_bits const  type, BRANCHING_PREDICATE const  predicate)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:   return compare(v1._boolean, v2._boolean, predicate);
        case type_of_input_bits::UINT8:     return compare(v1._uint8,   v2._uint8,   predicate);
        case type_of_input_bits::SINT8:     return compare(v1._sint8,   v2._sint8,   predicate);
        case type_of_input_bits::UINT16:    return compare(v1._uint16,  v2._uint16,  predicate);
        case type_of_input_bits::SINT16:    return compare(v1._sint16,  v2._sint16,  predicate);
        case type_of_input_bits::UINT32:    return compare(v1._uint32,  v2._uint32,  predicate);
        case type_of_input_bits::SINT32:    return compare(v1._sint32,  v2._sint32,  predicate);
        case type_of_input_bits::UINT64:    return compare(v1._uint64,  v2._uint64,  predicate);
        case type_of_input_bits::SINT64:    return compare(v1._sint64,  v2._sint64,  predicate);
        case type_of_input_bits::FLOAT32:   return compare(v1._float32, v2._float32, predicate);
        case type_of_input_bits::FLOAT64:   return compare(v1._float64, v2._float64, predicate);
        default: { UNREACHABLE(); } return false;
    }
}


std::size_t  hash(number_overlay const  value, type_of_input_bits const  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:   return (std::size_t)value._boolean;
        case type_of_input_bits::UINT8:     return (std::size_t)value._uint8;
        case type_of_input_bits::SINT8:     return (std::size_t)value._sint8;
        case type_of_input_bits::UINT16:    return (std::size_t)value._uint16;
        case type_of_input_bits::SINT16:    return (std::size_t)value._sint16;
        case type_of_input_bits::UINT32:    return (std::size_t)value._uint32;
        case type_of_input_bits::SINT32:    return (std::size_t)value._sint32;
        case type_of_input_bits::UINT64:    return (std::size_t)value._uint64;
        case type_of_input_bits::SINT64:    return (std::size_t)value._sint64;
        case type_of_input_bits::FLOAT32:   return (std::size_t)value._float32;
        case type_of_input_bits::FLOAT64:   return (std::size_t)value._float64;
        default: { UNREACHABLE(); } return 0UL;
    }
}


bool is_finite(number_overlay const  value, type_of_input_bits const  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:
            return *(natural_8_bit*)&value._boolean < 2U;
        case type_of_input_bits::UINT8:
        case type_of_input_bits::SINT8:
        case type_of_input_bits::UINT16:
        case type_of_input_bits::SINT16:
        case type_of_input_bits::UINT32:
        case type_of_input_bits::SINT32:
        case type_of_input_bits::UINT64:
        case type_of_input_bits::SINT64:
            return true;
        case type_of_input_bits::FLOAT32:
            return std::isfinite(value._float32) || !std::isnan(value._float32);
        case type_of_input_bits::FLOAT64:
            return std::isfinite(value._float64) || !std::isnan(value._float64);
        default: { UNREACHABLE(); } return false;
    }
}


template<typename T>
struct  extreme
{
    static_assert(std::is_arithmetic<T>::value, "'T' must be of an arithmetic type.");

    struct impl_i
    {
        static T get(T const  extreme, float_64_bit const  extreme_multiplier)
        {
            T const  result{ (T)std::round(extreme_multiplier * (float_64_bit)extreme) };
            return result;
        }
    };

    struct impl_f
    {
        static T get(T const  extreme, float_64_bit const  extreme_multiplier)
        {
            int  exponent;
            T const  fraction{ std::frexp(extreme, &exponent) };
            T const  new_exponent{ impl_i::get(exponent, extreme_multiplier) };
            T const  result{ fraction * (T)std::pow(2.0, new_exponent) };
            return result;
        }
    };

    using impl = typename std::conditional<std::is_integral<T>::value, impl_i, impl_f>::type;

    static inline T  lowest(float_64_bit const  extreme_multiplier)
    { return impl::get(std::numeric_limits<T>::lowest(), extreme_multiplier); }

    static inline T  highest(float_64_bit const  extreme_multiplier)
    { return impl::get(std::numeric_limits<T>::max(), extreme_multiplier); }

    static inline bool  test(T const  value, float_64_bit const  extreme_multiplier)
    { return (std::is_signed<T>::value && value < lowest(extreme_multiplier)) || value > highest(extreme_multiplier); }
};


bool is_high_extreme(number_overlay const  value, type_of_input_bits const  type, float_64_bit const  extreme_multiplier)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:  return *(natural_8_bit*)&value._boolean > 1U;
        case type_of_input_bits::UINT8:    return extreme<natural_8_bit>::test(value._uint8, extreme_multiplier);
        case type_of_input_bits::SINT8:    return extreme<integer_8_bit>::test(value._sint8, extreme_multiplier);
        case type_of_input_bits::UINT16:   return extreme<natural_16_bit>::test(value._uint16, extreme_multiplier);
        case type_of_input_bits::SINT16:   return extreme<integer_16_bit>::test(value._sint16, extreme_multiplier);
        case type_of_input_bits::UINT32:   return extreme<natural_32_bit>::test(value._uint32, extreme_multiplier);
        case type_of_input_bits::SINT32:   return extreme<integer_32_bit>::test(value._sint32, extreme_multiplier);
        case type_of_input_bits::UINT64:   return extreme<natural_64_bit>::test(value._uint64, extreme_multiplier);
        case type_of_input_bits::SINT64:   return extreme<integer_64_bit>::test(value._sint64, extreme_multiplier);
        case type_of_input_bits::FLOAT32:  return extreme<float_32_bit>::test(value._float32, extreme_multiplier);
        case type_of_input_bits::FLOAT64:  return extreme<float_64_bit>::test(value._float64, extreme_multiplier);
        default: { UNREACHABLE(); } return false;
    }
}


bool bit_value(number_overlay const  value, type_of_input_bits const  type, natural_8_bit const  bit_idx)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:  ASSUMPTION(bit_idx <  1U); return value._boolean;
        case type_of_input_bits::UINT8:    ASSUMPTION(bit_idx <  8U); return (value._uint8  & (1U << bit_idx)) != 0U;
        case type_of_input_bits::SINT8:    ASSUMPTION(bit_idx <  8U); return (value._sint8  & (1U << bit_idx)) != 0U;
        case type_of_input_bits::UINT16:   ASSUMPTION(bit_idx < 16U); return (value._uint16 & (1U << bit_idx)) != 0U;
        case type_of_input_bits::SINT16:   ASSUMPTION(bit_idx < 16U); return (value._sint16 & (1U << bit_idx)) != 0U;
        case type_of_input_bits::UINT32:   ASSUMPTION(bit_idx < 32U); return (value._uint32 & (1U << bit_idx)) != 0U;
        case type_of_input_bits::SINT32:   ASSUMPTION(bit_idx < 32U); return (value._sint32 & (1U << bit_idx)) != 0U;
        case type_of_input_bits::UINT64:   ASSUMPTION(bit_idx < 64U); return (value._uint64 & (1U << bit_idx)) != 0U;
        case type_of_input_bits::SINT64:   ASSUMPTION(bit_idx < 64U); return (value._sint64 & (1U << bit_idx)) != 0U;
        default: { UNREACHABLE(); } return false;
    }
}


vector_overlay  make_vector_overlay(vecf64 const&  v, type_vector const&  types)
{
    ASSUMPTION(size(v) == types.size());
    vector_overlay  result;
    for (std::size_t  i = 0UL; i != size(v); ++i)
        result.push_back(make_number_overlay(at(v, i), types.at(i)));
    return result;
}


bool compare(vector_overlay const&  v1, vector_overlay const&  v2, type_vector const&  types, BRANCHING_PREDICATE const  predicate)
{
    ASSUMPTION(v1.size() == v2.size() && v1.size() == types.size());
    auto  it1 = v1.begin();
    auto  it2 = v2.begin();
    auto  itt = types.begin();
    for ( ; it1 != v1.end(); ++it1, ++it2, ++itt)
        if (!compare(*it1, *it2, *itt, predicate))
            return false;
    return true;
}


std::size_t  hash(vector_overlay const&  v, type_vector const&  types)
{
    ASSUMPTION(v.size() == types.size());
    auto  ito = v.begin();
    auto  itt = types.begin();
    std::size_t  result{ 0UL };
    for ( ; ito != v.end(); ++ito, ++itt)
        ::hash_combine(result, hash(*ito, *itt));
    return result;
}


bool is_finite(vector_overlay const&  v, type_vector const&  types)
{
    ASSUMPTION(v.size() == types.size());
    auto  ito = v.begin();
    auto  itt = types.begin();
    for ( ; ito != v.end(); ++ito, ++itt)
        if (!is_finite(*ito, *itt))
            return false;
    return true;
}


bool has_high_extreme_coordinate(vector_overlay const&  v, type_vector const&  types, float_64_bit const  extreme_multiplier)
{
    ASSUMPTION(v.size() == types.size());
    auto  ito = v.begin();
    auto  itt = types.begin();
    for ( ; ito != v.end(); ++ito, ++itt)
        if (is_high_extreme(*ito, *itt, extreme_multiplier))
            return true;
    return false;
}


float_64_bit  smallest_step(float_64_bit  from, type_of_input_bits  type, bool  negative)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:
            return negative ? -from : 1.0 - from;
        case type_of_input_bits::UINT8:
        case type_of_input_bits::SINT8:
        case type_of_input_bits::UINT16:
        case type_of_input_bits::SINT16:
        case type_of_input_bits::UINT32:
        case type_of_input_bits::SINT32:
        case type_of_input_bits::UINT64:
        case type_of_input_bits::SINT64:
            {
                float_64_bit  step{ negative ? std::floor(from) - from : std::ceil(from) - from };
                if (step == 0.0)
                    step = negative ? std::min(-1.0, std::nextafter(from, -std::numeric_limits<float_64_bit>::infinity()) - from)
                                    : std::max( 1.0, std::nextafter(from,  std::numeric_limits<float_64_bit>::infinity()) - from);
                return step;
            }
            break;
        case type_of_input_bits::FLOAT32:
            return (float_64_bit)std::nextafter(make_number_overlay(from, type)._float32, 
                                                negative ? -std::numeric_limits<float_32_bit>::infinity() :
                                                            std::numeric_limits<float_32_bit>::infinity()) - from;
        case type_of_input_bits::FLOAT64:
            return std::nextafter(from, negative ? -std::numeric_limits<float_64_bit>::infinity() :
                                                    std::numeric_limits<float_64_bit>::infinity()) - from;
        default: { UNREACHABLE(); } return 0UL;
    }
}


vecf64  smallest_step(vecf64 const&  from, type_vector const&  types, vecf64 const&  direction)
{
    ASSUMPTION(from.size() == types.size() && from.size() == size(direction));
    auto  itf = from.begin();
    auto  itt = types.begin();
    auto  itd = direction.begin();
    vecf64  result;
    for ( ; itf != from.end(); ++itf, ++itt, ++itd)
        result.push_back(smallest_step(*itf, *itt, *itd < 0.0));
    return result;

}


}
