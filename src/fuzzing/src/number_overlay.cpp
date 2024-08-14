#include <fuzzing/number_overlay.hpp>
#include <utility/assumptions.hpp>
#include <utility/hash_combine.hpp>

namespace  fuzzing {


bool compare(number_overlay const  v1, number_overlay const  v2, type_identifier const  type, comparator_type const  predicate)
{
    switch (type)
    {
        case type_identifier::BOOLEAN:   return compare(v1._boolean, v2._boolean, predicate);
        case type_identifier::UINT8:     return compare(v1._uint8,   v2._uint8,   predicate);
        case type_identifier::SINT8:     return compare(v1._uint8,   v2._uint8,   predicate);
        case type_identifier::UINT16:    return compare(v1._uint16,  v2._uint16,  predicate);
        case type_identifier::SINT16:    return compare(v1._sint16,  v2._sint16,  predicate);
        case type_identifier::UINT32:    return compare(v1._uint32,  v2._uint32,  predicate);
        case type_identifier::SINT32:    return compare(v1._sint32,  v2._sint32,  predicate);
        case type_identifier::UINT64:    return compare(v1._sint32,  v2._sint32,  predicate);
        case type_identifier::SINT64:    return compare(v1._sint64,  v2._sint64,  predicate);
        case type_identifier::FLOAT32:   return compare(v1._float32, v2._float32, predicate);
        case type_identifier::FLOAT64:   return compare(v1._float64, v2._float64, predicate);
        default: { UNREACHABLE(); } return false;
    }
}


std::size_t  hash(number_overlay const  value, type_identifier const  type)
{
    switch (type)
    {
        case type_identifier::BOOLEAN:   return (std::size_t)value._boolean;
        case type_identifier::UINT8:     return (std::size_t)value._uint8;
        case type_identifier::SINT8:     return (std::size_t)value._uint8;
        case type_identifier::UINT16:    return (std::size_t)value._uint16;
        case type_identifier::SINT16:    return (std::size_t)value._sint16;
        case type_identifier::UINT32:    return (std::size_t)value._uint32;
        case type_identifier::SINT32:    return (std::size_t)value._sint32;
        case type_identifier::UINT64:    return (std::size_t)value._sint32;
        case type_identifier::SINT64:    return (std::size_t)value._sint64;
        case type_identifier::FLOAT32:   return (std::size_t)value._float32;
        case type_identifier::FLOAT64:   return (std::size_t)value._float64;
        default: { UNREACHABLE(); } return 0UL;
    }
}


number_overlay  add(number_overlay  value, type_identifier const  type, float_64_bit const  delta)
{
    switch (type)
    {
        case type_identifier::BOOLEAN:
            value._boolean = std::fabs(delta) < 0.5 ? false : true;
            break;
        case type_identifier::UINT8:
            value._uint8 = (natural_8_bit)((integer_8_bit)value._uint8 + (integer_8_bit)std::round(delta));
            break;
        case type_identifier::SINT8:
            value._sint8 += (integer_8_bit)std::round(delta);
            break;
        case type_identifier::UINT16:
            value._uint16 = (natural_16_bit)((integer_16_bit)value._uint16 + (integer_16_bit)std::round(delta));
            break;
        case type_identifier::SINT16:
            value._sint16 += (integer_16_bit)std::round(delta);
            break;
        case type_identifier::UINT32:
            value._uint32 = (natural_32_bit)((integer_32_bit)value._uint32 + (integer_32_bit)std::round(delta));
            break;
        case type_identifier::SINT32:
            value._sint32 += (integer_32_bit)std::round(delta);
            break;
        case type_identifier::UINT64:
            value._uint64 = (natural_64_bit)((integer_64_bit)value._uint64 + (integer_64_bit)std::round(delta));
            break;
        case type_identifier::SINT64:
            value._sint64 += (integer_64_bit)std::round(delta);
            break;
        case type_identifier::FLOAT32:
            value._float32 += (float_32_bit)delta;
            break;
        case type_identifier::FLOAT64:
            value._float64 += delta;
            break;
        default: { UNREACHABLE(); }
    }
    return value;
}


bool compare(vector_overlay const&  v1, vector_overlay const&  v2, type_vector const&  types, comparator_type const  predicate)
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


void  add(vector_overlay&  v, type_vector const&  types, vecf64 const&  delta)
{
    ASSUMPTION(v.size() == types.size() && v.size() == delta.size());
    auto  ito = v.begin();
    auto  itt = types.begin();
    auto  itd = delta.begin();
    std::size_t  result{ 0UL };
    for ( ; ito != v.end(); ++ito, ++itt, ++itd)
        *ito = add(*ito, *itt, *itd);
}


vector_overlay  add_cp(vector_overlay const&  v, type_vector const&  types, vecf64 const&  delta)
{
    vector_overlay  result{ v };
    add(result, types, delta);
    return result;
}


}
