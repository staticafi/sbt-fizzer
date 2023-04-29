#ifndef INSTRUMENTATION_data_record_id_HPP_INCLUDED
#   define INSTRUMENTATION_data_record_id_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

namespace instrumentation {

enum class data_record_id: natural_8_bit {
    invalid,
    termination,
    condition,
    br_instr,
    stdin_bytes
};

}


#endif