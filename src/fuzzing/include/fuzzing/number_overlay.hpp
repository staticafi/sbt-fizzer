#ifndef FUZZING_NUMBER_OVERLAY_HPP_INCLUDED
#   define FUZZING_NUMBER_OVERLAY_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/invariants.hpp>
#   include <vector>

namespace  fuzzing {


using  comparator_type = instrumentation::BRANCHING_PREDICATE;


using  type_identifier = instrumentation::type_of_input_bits; 
using  type_vector = std::vector<type_identifier>; 


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


template<typename T>
T  cast_float_value(float_64_bit  value)
{
    if (std::numeric_limits<T>::is_integer)
        value = std::round(value);
    if (value <= (float_64_bit)std::numeric_limits<T>::lowest())
        return std::numeric_limits<T>::lowest();
    if (value >= (float_64_bit)std::numeric_limits<T>::max())
        return std::numeric_limits<T>::max();
    return (T)value;
}


template<typename T>
bool compare(T const  v1, T const  v2, comparator_type const  predicate)
{
    switch (predicate)
    {
        case comparator_type::BP_EQUAL:          return v1 == v2;
        case comparator_type::BP_UNEQUAL:        return v1 != v2;
        case comparator_type::BP_LESS:           return v1 < v2;
        case comparator_type::BP_LESS_EQUAL:     return v1 <= v2;
        case comparator_type::BP_GREATER:        return v1 > v2;
        case comparator_type::BP_GREATER_EQUAL:  return v1 >= v2;
        default: { UNREACHABLE(); } return false;
    }
}


template<typename T>
T as(number_overlay const  value, type_identifier const  type)
{
    switch (type)
    {
        case type_identifier::BOOLEAN:   return (T)value._boolean;
        case type_identifier::UINT8:     return (T)value._uint8;
        case type_identifier::SINT8:     return (T)value._sint8;
        case type_identifier::UINT16:    return (T)value._uint16;
        case type_identifier::SINT16:    return (T)value._sint16;
        case type_identifier::UINT32:    return (T)value._uint32;
        case type_identifier::SINT32:    return (T)value._sint32;
        case type_identifier::UINT64:    return (T)value._uint64;
        case type_identifier::SINT64:    return (T)value._sint64;
        case type_identifier::FLOAT32:   return (T)value._float32;
        case type_identifier::FLOAT64:   return (T)value._float64;
        default: { UNREACHABLE(); } return false;
    }
}

number_overlay  make_number_overlay(float_64_bit const  value, type_identifier const  type);
bool compare(number_overlay  v1, number_overlay  v2, type_identifier  type, comparator_type  predicate);
std::size_t  hash(number_overlay  value, type_identifier  type);
bool is_finite(number_overlay  value, type_identifier  type);
bool is_high_extreme(number_overlay  value, type_identifier  type, float_64_bit  extreme_multiplier = 0.95);


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
bool compare(vector_overlay const&  v1, vector_overlay const&  v2, type_vector const&  types, comparator_type  predicate);
std::size_t  hash(vector_overlay const&  v, type_vector const&  types);
bool is_finite(vector_overlay const&  v, type_vector const&  types);
bool has_high_extreme_coordinate(vector_overlay const&  v, type_vector const&  types, float_64_bit  extreme_multiplier = 0.95);


float_64_bit  smallest_step(float_64_bit  from, type_identifier  type, bool  negative);
vecf64  smallest_step(vecf64 const&  from, type_vector const&  types, vecf64 const&  direction);


}

#endif