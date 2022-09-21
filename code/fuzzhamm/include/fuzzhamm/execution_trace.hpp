#ifndef FUZZHAMM_EXECUTION_TRACE_HPP_INCLUDED
#   define FUZZHAMM_EXECUTION_TRACE_HPP_INCLUDED

#   include <fuzzhamm/branching_fuzzer_sequence.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <unordered_map>
#   include <unordered_set>
#   include <memory>

namespace  fuzzhamm {


using namespace instrumentation;


enum struct  EXECUTION_TRACE_STATE
{
    CONSTRUCTION            = 0,
    DISCOVERING_BITS        = 1,
    FUZZING_BITS            = 2,
};


struct  execution_trace_record
{
    branching_coverage_info   coverage_info;
    std::unordered_set<natural_16_bit>  sensitive_stdin_bits;
    std::unordered_set<natural_16_bit>  diverged_stdin_bits;
    std::unordered_set<natural_16_bit>  colliding_stdin_bits;
    branching_fuzzer_sequence_ptr  fuzzer;
};


using  execution_trace_hash_code = natural_64_bit;

struct  sensitivity_fuzzer_base;
using  sensitivity_fuzzer_base_ptr = std::shared_ptr<sensitivity_fuzzer_base>;


struct  execution_trace
{
    execution_trace();

    execution_trace_hash_code  hash_code;
    EXECUTION_TRACE_STATE  state;
    std::vector<execution_trace_record>  branching_records;
    std::unordered_map<location_id, std::unordered_set<natural_32_bit> >  uncovered_branchings;
    std::vector<bool>  input_stdin;
    std::vector<natural_8_bit>  input_stdin_counts;
    sensitivity_fuzzer_base_ptr  fuzzer;
    std::unordered_set<natural_16_bit>  sensitive_stdin_bits;
    integer_32_bit  fuzzed_record_idx;
};


using  execution_trace_ptr = std::shared_ptr<execution_trace>;
using  execution_trace_const_ptr = std::shared_ptr<execution_trace const>;

using  execution_trace_weak_ptr = std::weak_ptr<execution_trace>;
using  execution_trace_weak_const_ptr = std::weak_ptr<execution_trace const>;


}

#endif
