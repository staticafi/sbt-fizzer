#ifndef FUZZHAMM_SENSITIVITY_FUZZER_SIMILAR_TRACE_SEARCH_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_SIMILAR_TRACE_SEARCH_HPP_INCLUDED

#   include <fuzzhamm/sensitivity_fuzzer_base.hpp>
#   include <utility/math.hpp>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_similar_trace_search : public sensitivity_fuzzer_base
{
    explicit sensitivity_fuzzer_similar_trace_search(
            execution_trace_ptr  the_trace,
            sensitivity_fuzzer_base_ptr  parent,
            bool  consider_only_uncovered_branchings_
            );

    [[nodiscard]] execution_trace_ptr  get_similar_trace() const { return similar_trace; }

protected:

    void  update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index) override;
    void  mutate(vecb&  input_stdin) override;
    bool  done() override;

private:
    std::unordered_set<natural_16_bit>  sensitive_stdin_bits;
    natural_8_bit  counter;
    natural_8_bit  max_counter;
    execution_trace_ptr  similar_trace;
    bool  consider_only_uncovered_branchings;
};


}

#endif
