#include <instrumentation/instrumentation_types.hpp>
#include <utility/invariants.hpp>
#include <ostream>

namespace  instrumentation {


branching_coverage_info::branching_coverage_info(location_id const  id_)
    : id{id_}
    , direction{}
    , value{}
    , idx_to_br_instr{}
    , xor_like_branching_function{}
{}

size_t branching_coverage_info::flattened_size() {
    return sizeof(id) + sizeof(direction) + sizeof(value) + sizeof(idx_to_br_instr) + sizeof(xor_like_branching_function);
}

br_instr_coverage_info::br_instr_coverage_info(location_id const  id)
    : br_instr_id(id)
    , covered_branch{}
{}

size_t br_instr_coverage_info::flattened_size() {
    return sizeof(br_instr_id) + sizeof(covered_branch);
}



bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r)
{
    return l.id == r.id && l.direction == r.direction;
}

std::ostream&  operator<<(std::ostream&  ostr, location_id const  id)
{
    ostr << id.id << '!' << id.context_hash;
    return ostr;
}


type_of_input_bits  from_id(natural_8_bit const  id)
{
    switch (id)
    {
        case  0U: return type_of_input_bits::BOOLEAN;

        case  1U: return type_of_input_bits::UINT8;
        case  2U: return type_of_input_bits::SINT8;

        case  3U: return type_of_input_bits::UINT16;
        case  4U: return type_of_input_bits::SINT16;

        case  5U: return type_of_input_bits::UINT32;
        case  6U: return type_of_input_bits::SINT32;

        case  7U: return type_of_input_bits::UINT64;
        case  8U: return type_of_input_bits::SINT64;

        case  9U: return type_of_input_bits::FLOAT32;
        case 10U: return type_of_input_bits::FLOAT64;

        case 11U: return type_of_input_bits::UNTYPED8;
        case 12U: return type_of_input_bits::UNTYPED16;
        case 13U: return type_of_input_bits::UNTYPED32;
        case 14U: return type_of_input_bits::UNTYPED64;

        default: { UNREACHABLE(); return type_of_input_bits::UINT8; }
    }
}


bool  is_known_type(type_of_input_bits const  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:
        case type_of_input_bits::UINT8:
        case type_of_input_bits::SINT8:
        case type_of_input_bits::UINT16:
        case type_of_input_bits::SINT16:
        case type_of_input_bits::UINT32:
        case type_of_input_bits::SINT32:
        case type_of_input_bits::FLOAT32:
        case type_of_input_bits::UINT64:
        case type_of_input_bits::SINT64:
        case type_of_input_bits::FLOAT64:
            return true;
        case type_of_input_bits::UNTYPED8:
        case type_of_input_bits::UNTYPED16:
        case type_of_input_bits::UNTYPED32:
        case type_of_input_bits::UNTYPED64:
            return false;
        default: { UNREACHABLE(); return false; }
    }
}


std::string  to_string(type_of_input_bits  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN: return "BOOLEAN";
        case type_of_input_bits::UINT8: return "UINT8";
        case type_of_input_bits::SINT8: return "SINT8";
        case type_of_input_bits::UINT16: return "UINT16";
        case type_of_input_bits::SINT16: return "SINT16";
        case type_of_input_bits::UINT32: return "UINT32";
        case type_of_input_bits::SINT32: return "SINT32";
        case type_of_input_bits::FLOAT32: return "FLOAT32";
        case type_of_input_bits::UINT64: return "UINT64";
        case type_of_input_bits::SINT64: return "SINT64";
        case type_of_input_bits::FLOAT64: return "FLOAT64";
        case type_of_input_bits::UNTYPED8: return "UNTYPED8";
        case type_of_input_bits::UNTYPED16: return "UNTYPED16";
        case type_of_input_bits::UNTYPED32: return "UNTYPED32";
        case type_of_input_bits::UNTYPED64: return "UNTYPED64";
        default: { UNREACHABLE(); return "ERROR"; }
    }
}


natural_8_bit  num_bytes(type_of_input_bits const  type)
{
    switch (type)
    {
        case type_of_input_bits::BOOLEAN:
        case type_of_input_bits::UINT8:
        case type_of_input_bits::SINT8:
        case type_of_input_bits::UNTYPED8:
            return 1U;
        case type_of_input_bits::UINT16:
        case type_of_input_bits::SINT16:
        case type_of_input_bits::UNTYPED16:
            return 2U;
        case type_of_input_bits::UINT32:
        case type_of_input_bits::SINT32:
        case type_of_input_bits::FLOAT32:
        case type_of_input_bits::UNTYPED32:
            return 4U;
        case type_of_input_bits::UINT64:
        case type_of_input_bits::SINT64:
        case type_of_input_bits::FLOAT64:
        case type_of_input_bits::UNTYPED64:
            return 8U;
        default: { UNREACHABLE(); return 0U; }
    }
}


std::ostream&  save_value(std::ostream&  ostr, type_of_input_bits const  type, void* const  value_ptr)
{
    ostr << std::dec;
    switch (type)
    {
        case type_of_input_bits::BOOLEAN: ostr << (*(natural_8_bit const*)value_ptr == 0 ? 0 : 1); break;

        case type_of_input_bits::UINT8: ostr << *(natural_8_bit const*)value_ptr; break;
        case type_of_input_bits::SINT8: ostr << *(integer_8_bit const*)value_ptr; break;

        case type_of_input_bits::UINT16: ostr << *(natural_16_bit const*)value_ptr; break;
        case type_of_input_bits::SINT16: ostr << *(integer_16_bit const*)value_ptr; break;

        case type_of_input_bits::UINT32: ostr << *(natural_32_bit const*)value_ptr; break;
        case type_of_input_bits::SINT32: ostr << *(integer_32_bit const*)value_ptr; break;

        case type_of_input_bits::UINT64: ostr << *(natural_64_bit const*)value_ptr; break;
        case type_of_input_bits::SINT64: ostr << *(integer_64_bit const*)value_ptr; break;

        case type_of_input_bits::FLOAT32: ostr << *(float_32_bit const*)value_ptr; break;
        case type_of_input_bits::FLOAT64: ostr << *(float_64_bit const*)value_ptr; break;

        case type_of_input_bits::UNTYPED8: ostr << *(natural_8_bit const*)value_ptr; break;
        case type_of_input_bits::UNTYPED16: ostr << *(natural_16_bit const*)value_ptr; break;
        case type_of_input_bits::UNTYPED32: ostr << *(natural_32_bit const*)value_ptr; break;
        case type_of_input_bits::UNTYPED64: ostr << *(natural_64_bit const*)value_ptr; break;

        default: { UNREACHABLE(); }
    }
    return ostr;
}


}
