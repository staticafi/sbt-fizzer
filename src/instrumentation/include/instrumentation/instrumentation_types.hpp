#ifndef INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED
#   define INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <functional>
#   include <iosfwd>

namespace  instrumentation {


union location_id
{
    using  id_type = natural_32_bit;
    using  context_type = natural_32_bit;

    location_id(id_type const  id_, context_type const  context_hash_ = 0U)
        : id { id_ }
        , context_hash { context_hash_ }
    {}

    struct
    {
        id_type  id;
        context_type  context_hash;
    };

    natural_64_bit  uid;
};

inline bool operator==(location_id const l, location_id const r) { return l.uid == r.uid; }
inline bool operator!=(location_id const l, location_id const r) { return l.uid != r.uid; }
inline bool operator<(location_id const l, location_id const r) { return l.id < r.id || (l.id == r.id && l.context_hash < r.context_hash); }
inline location_id  invalid_location_id() { return {0U}; }
std::ostream&  operator<<(std::ostream&  ostr, location_id  id);


using branching_function_value_type = float_64_bit;


enum BRANCHING_PREDICATE : natural_8_bit
{
    BP_EQUAL           = 0,
    BP_UNEQUAL         = 1,
    BP_LESS            = 2,
    BP_LESS_EQUAL      = 3,
    BP_GREATER         = 4,
    BP_GREATER_EQUAL   = 5
};

BRANCHING_PREDICATE opposite_predicate(BRANCHING_PREDICATE  predicate);


struct  branching_coverage_info
{
    explicit branching_coverage_info(location_id const  id_);
    static size_t flattened_size();

    location_id  id;
    bool  direction;
    branching_function_value_type  value;
    natural_32_bit  idx_to_br_instr;
    bool xor_like_branching_function;
    BRANCHING_PREDICATE predicate;
    natural_32_bit  num_input_bytes;
};


struct  br_instr_coverage_info
{
    explicit br_instr_coverage_info(location_id const  id);
    static size_t flattened_size();

    location_id  br_instr_id;
    bool  covered_branch;
};


bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r);


enum struct  type_of_input_bits : natural_8_bit
{
    // Known types:

    BOOLEAN = 0U,

    UINT8 = 1U,
    SINT8 = 2U,

    UINT16 = 3U,
    SINT16 = 4U,

    UINT32 = 5U,
    SINT32 = 6U,

    UINT64 = 7U,
    SINT64 = 8U,

    FLOAT32 = 9U,
    FLOAT64 = 10U,

    // Unknown types:

    UNTYPED8 = 11U,
    UNTYPED16 = 12U,
    UNTYPED32 = 13U,
    UNTYPED64 = 14U
};

inline natural_8_bit  to_id(type_of_input_bits const  type) { return (natural_8_bit)type; }
type_of_input_bits  from_id(natural_8_bit  id);

bool  is_known_type(type_of_input_bits  type);
bool  is_numeric_type(type_of_input_bits  type);

std::string  to_string(type_of_input_bits  type);
std::string  to_c_type_string(type_of_input_bits  type);

natural_8_bit  num_bytes(type_of_input_bits  type);
inline natural_8_bit  num_bits(type_of_input_bits const  type) { return (natural_8_bit)(8U * num_bytes(type)); }

std::ostream&  save_value(std::ostream&  ostr, type_of_input_bits  type, void const*  value_ptr);


}


template<> struct std::hash<instrumentation::location_id> {
    std::size_t operator()(instrumentation::location_id const id) const noexcept { return id.uid; }
};


#endif
