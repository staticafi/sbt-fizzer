#ifndef INSTRUMENTATION_FUZZ_TARGET_HPP_INCLUDED
#   define INSTRUMENTATION_FUZZ_TARGET_HPP_INCLUDED

#   include <memory>
#   include <utility/basic_numeric_types.hpp>
#   include <vector>
#   include <unordered_set>
#   include <connection/shared_memory.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <connection/shared_memory.hpp>
#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_void.hpp>
#   include <iomodels/configuration.hpp>


namespace  instrumentation {

class fuzz_target {

    natural_32_bit trace_length;
    natural_32_bit br_instr_trace_length;
    std::vector<natural_32_bit> context_hashes;
    std::unordered_set<natural_32_bit> locations;
    iomodels::configuration config;
    iomodels::stdin_base_ptr stdin_model;
    iomodels::stdout_base_ptr stdout_model;
    connection::shared_memory shared_memory;

public:

    fuzz_target();

    void process_condition(
            location_id::id_type id_type,
            bool direction,
            branching_function_value_type value,
            bool xor_like_branching_function,
            natural_8_bit predicate
            );
    void process_br_instr(location_id id, bool covered_branch);

    void process_call_begin(natural_32_bit const  id);
    void process_call_end(natural_32_bit const  id);

    void on_read(natural_8_bit* ptr, type_of_input_bits type);
    void on_write(natural_8_bit const*  ptr, type_of_input_bits type);

    connection::shared_memory& get_shared_memory() { return shared_memory; }

    void load_config();
    void load_stdin();
    void load_stdout();

};

extern std::unique_ptr<fuzz_target> sbt_fizzer_target;

}

#endif