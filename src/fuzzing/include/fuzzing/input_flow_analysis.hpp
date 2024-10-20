#ifndef FUZZING_INPUT_FLOW_ANALYSIS_HPP_INCLUDED
#   define FUZZING_INPUT_FLOW_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_base.hpp>
#   include <iomodels/configuration.hpp>
#   include <sala/program.hpp>
#   include <unordered_set>
#   include <map>
#   include <set>
#   include <memory>

namespace  fuzzing {


struct  input_flow_analysis
{
    struct  io_models_setup
    {
        iomodels::stdin_base_ptr  stdin_ptr{ nullptr };
        iomodels::stdout_base_ptr  stdout_ptr{ nullptr };
        iomodels::configuration  io_config{};
    };

    struct  computation_io_data
    {
        // Input
        stdin_bits_and_types_pointer  input_ptr{ nullptr };
        execution_trace_pointer  trace_ptr{ nullptr };
        trace_index_type  trace_size{ 0U };
        float_64_bit remaining_seconds{ 0.0 };

        // Output
        std::vector<std::unordered_set<stdin_bit_index> >  sensitive_bits{};
    };

    struct  performance_statistics
    {
        std::size_t  num_successes{ 0 };
        std::size_t  num_failures{ 0 };
        std::unordered_set<std::string>  errors{};
        std::unordered_set<std::string>  warnings{};
        std::map<std::pair<trace_index_type,natural_32_bit>, std::set<float_64_bit> >  complexity{};
    };

    explicit input_flow_analysis(sala::Program const* sala_program_ptr, io_models_setup const* io_setup_ptr_);

    void  run(computation_io_data*  data_ptr_);

    computation_io_data const&  data() const { return *data_ptr; }
    computation_io_data&  data() { return *data_ptr; }

    io_models_setup const&  io_setup() const { return *io_setup_ptr; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    struct input_flow;

    sala::Program const* program_ptr;
    io_models_setup const* io_setup_ptr;
    computation_io_data*  data_ptr;

    performance_statistics  statistics;
};


}

#endif
