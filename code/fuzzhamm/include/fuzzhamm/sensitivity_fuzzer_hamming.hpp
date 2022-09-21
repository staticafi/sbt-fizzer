#ifndef FUZZHAMM_SENSITIVITY_FUZZER_HAMMING_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_HAMMING_HPP_INCLUDED

#   include <fuzzhamm/sensitivity_fuzzer_base.hpp>
#   include <utility/math.hpp>
#   include <vector>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_hamming : public sensitivity_fuzzer_base
{
    explicit sensitivity_fuzzer_hamming(
            execution_trace_weak_ptr  the_trace,
            natural_16_bit  num_bit_indices,
            sensitivity_fuzzer_base_weak_ptr  parent_ptr
            );

protected:

    void  update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index) override;
    void  mutate(vecb&  input_stdin) override;
    bool  done() override;

private:
    std::vector<natural_16_bit>  bit_indices;
    bool  finished;
};


}

#endif
