#ifndef FUZZHAMM_SENSITIVITY_FUZZER_BASE_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_BASE_HPP_INCLUDED

#   include <fuzzhamm/execution_trace.hpp>
#   include <utility/math.hpp>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_base;
using  sensitivity_fuzzer_base_weak_ptr = std::weak_ptr<sensitivity_fuzzer_base>;


struct  sensitivity_fuzzer_base
{
    explicit  sensitivity_fuzzer_base(execution_trace_weak_ptr  the_trace, sensitivity_fuzzer_base_weak_ptr  parent_ptr);
    virtual  ~sensitivity_fuzzer_base() = default;

    [[nodiscard]] execution_trace_ptr  trace() const { return trace_.lock(); }
    [[nodiscard]] sensitivity_fuzzer_base_ptr  parent() const { return parent_.lock(); }
    [[nodiscard]] std::size_t num_bits() const { return trace()->input_stdin.size(); }
    random_generator_for_natural_32_bit&  generator_ref() { return generator; }
    [[nodiscard]] natural_32_bit  num_generated_inputs() const { return num_inputs_generated; }
    [[nodiscard]] natural_32_bit  num_generated_inputs_total() const
    { return parent() == nullptr ? num_generated_inputs() : parent()->num_generated_inputs_total(); }

    void  on_sample(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index);
    void  compute_input(vecb&  input_stdin);

    virtual bool  done();

protected:

    virtual void  update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index) {}
    virtual void  mutate(vecb&  input_stdin) {}

    void  update_per_branching(
            execution_trace_const_ptr  sample_trace,
            std::size_t  diverging_branch_index,
            std::vector<natural_16_bit> const&  bit_indices
            );

private:

    sensitivity_fuzzer_base_weak_ptr  parent_;
    execution_trace_weak_ptr  trace_;
    random_generator_for_natural_32_bit   generator;
    natural_32_bit  num_inputs_generated;
};


}

#endif