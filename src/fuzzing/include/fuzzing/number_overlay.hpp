#ifndef FUZZING_NUMBER_OVERLAY_HPP_INCLUDED
#   define FUZZING_NUMBER_OVERLAY_HPP_INCLUDED

#   include <fuzzing/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/invariants.hpp>
#   include <vector>

namespace  fuzzing {


using  type_vector = std::vector<type_of_input_bits>; 


union  number_overlay
{
    number_overlay() : _uint64{ 0ULL } {}
    bool  _boolean;
    natural_8_bit  _uint8;
    integer_8_bit  _sint8;
    natural_16_bit  _uint16;
    integer_16_bit  _sint16;
    natural_32_bit  _uint32;
    integer_32_bit  _sint32;
    natural_64_bit  _uint64;
    integer_64_bit  _sint64;
    float_32_bit  _float32;
    float_64_bit  _float64;
};


using  vector_overlay = std::vector<number_overlay>;


template<typename R, typename T>
R  cast_float_value(T  value)
{
    static_assert(std::is_floating_point<T>::value, "'T' must be of an floating point type.");

    if (std::isnan(value))
        value = std::numeric_limits<T>::max();
    else if (value < std::numeric_limits<T>::lowest())
        value = std::numeric_limits<T>::lowest();
    else if (value > std::numeric_limits<T>::max())
        value = std::numeric_limits<T>::max();
    if (std::numeric_limits<R>::is_integer)
        value = std::round(value);

    if ((float_64_bit)value <= (float_64_bit)std::numeric_limits<R>::lowest())
        return std::numeric_limits<R>::lowest();
    if ((float_64_bit)value >= (float_64_bit)std::numeric_limits<R>::max())
        return std::numeric_limits<R>::max();
    return (T)value;
}


template<typename T>
bool compare(T const  v1, T const  v2, BRANCHING_PREDICATE const  predicate)
{
    switch (predicate)
    {
        case BRANCHING_PREDICATE::BP_EQUAL:          return v1 == v2;
        case BRANCHING_PREDICATE::BP_UNEQUAL:        return v1 != v2;
        case BRANCHING_PREDICATE::BP_LESS:           return v1 < v2;
        case BRANCHING_PREDICATE::BP_LESS_EQUAL:     return v1 <= v2;
        case BRANCHING_PREDICATE::BP_GREATER:        return v1 > v2;
        case BRANCHING_PREDICATE::BP_GREATER_EQUAL:  return v1 >= v2;
        default: { UNREACHABLE(); } return false;
    }
}


template<typename T>
T as(number_overlay const  value, type_of_input_bits const  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:   return value._boolean == false ? (T)0 : (T)1;
        case type_of_input_bits::UINT8:     return (T)value._uint8;
        case type_of_input_bits::SINT8:     return (T)value._sint8;
        case type_of_input_bits::UINT16:    return (T)value._uint16;
        case type_of_input_bits::SINT16:    return (T)value._sint16;
        case type_of_input_bits::UINT32:    return (T)value._uint32;
        case type_of_input_bits::SINT32:    return (T)value._sint32;
        case type_of_input_bits::UINT64:    return (T)value._uint64;
        case type_of_input_bits::SINT64:    return (T)value._sint64;
        case type_of_input_bits::FLOAT32:   return cast_float_value<T>(value._float32);
        case type_of_input_bits::FLOAT64:   return cast_float_value<T>(value._float64);
        default: { UNREACHABLE(); } return false;
    }
}

number_overlay  make_number_overlay(float_64_bit const  value, type_of_input_bits const  type);
bool compare(number_overlay  v1, number_overlay  v2, type_of_input_bits  type, BRANCHING_PREDICATE  predicate);
std::size_t  hash(number_overlay  value, type_of_input_bits  type);
bool is_finite(number_overlay  value, type_of_input_bits  type);
bool is_high_extreme(number_overlay  value, type_of_input_bits  type, float_64_bit  extreme_multiplier = 0.95);


template<typename T>
vec<T> as(vector_overlay const&  v, type_vector const&  types)
{
    ASSUMPTION(size(v) == types.size());
    vec<T>  result;
    for (std::size_t  i = 0UL; i != size(v); ++i)
        result.push_back(as<T>(at(v, i), types.at(i)));
    return result;
}

vector_overlay  make_vector_overlay(vecf64 const&  v, type_vector const&  types);
bool compare(vector_overlay const&  v1, vector_overlay const&  v2, type_vector const&  types, BRANCHING_PREDICATE  predicate);
std::size_t  hash(vector_overlay const&  v, type_vector const&  types);
bool is_finite(vector_overlay const&  v, type_vector const&  types);
bool has_high_extreme_coordinate(vector_overlay const&  v, type_vector const&  types, float_64_bit  extreme_multiplier = 0.95);


float_64_bit  smallest_step(float_64_bit  from, type_of_input_bits  type, bool  negative);
vecf64  smallest_step(vecf64 const&  from, type_vector const&  types, vecf64 const&  direction);


}

#endif
