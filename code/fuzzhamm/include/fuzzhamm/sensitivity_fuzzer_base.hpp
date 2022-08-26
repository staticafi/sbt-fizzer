#ifndef FUZZHAMM_SENSITIVITY_FUZZER_BASE_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_BASE_HPP_INCLUDED

#   include <fuzzhamm/execution_trace.hpp>
#   include <utility/math.hpp>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_base
{
    explicit  sensitivity_fuzzer_base(execution_trace_ptr  the_trace, sensitivity_fuzzer_base_ptr  parent_ptr = nullptr);
    virtual  ~sensitivity_fuzzer_base() = default;

    [[nodiscard]] execution_trace_ptr  trace() const { return trace_; }
    [[nodiscard]] sensitivity_fuzzer_base_ptr  parent() const { return parent_; }
    [[nodiscard]] std::size_t num_bits() const { return trace()->input_stdin.size(); }
    random_generator_for_natural_32_bit&  generator_ref() { return generator; }
    [[nodiscard]] natural_32_bit  num_generated_inputs() const { return num_inputs_generated; }
    [[nodiscard]] natural_32_bit  num_generated_inputs_total() const
    { return parent() == nullptr ? num_generated_inputs() : parent()->num_generated_inputs_total(); }

    void  on_sample(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index);
    void  compute_input(vecb&  input_stdin);

    virtual bool  done();

    void  record_sensitive_bit_index_at_branching(natural_16_bit  sensitive_bit_index, std::size_t  branching_index, bool  diverged);

protected:

    virtual void  update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index) {}
    virtual void  mutate(vecb&  input_stdin) {}

    void  update_per_branching(
            execution_trace_const_ptr  sample_trace,
            std::size_t  diverging_branch_index,
            std::function<void(std::size_t, bool)> const&  sensitive_bit_indices_recorder
            );

private:

    sensitivity_fuzzer_base_ptr  parent_;
    execution_trace_ptr  trace_;
    random_generator_for_natural_32_bit   generator;
    natural_32_bit  num_inputs_generated;
};


}

#endif
