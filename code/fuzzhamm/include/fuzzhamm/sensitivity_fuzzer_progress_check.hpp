#ifndef FUZZHAMM_SENSITIVITY_FUZZER_PROGRESS_CHECK_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_PROGRESS_CHECK_HPP_INCLUDED

#   include <fuzzhamm/sensitivity_fuzzer_base.hpp>
#   include <utility/math.hpp>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_progress_check : public sensitivity_fuzzer_base
{
    sensitivity_fuzzer_progress_check(
            execution_trace_ptr  the_trace,
            execution_trace_ptr  original_trace_,
            sensitivity_fuzzer_base_ptr  parent,
            bool  similarity_only_for_uncovered_branchings_
            );

    [[nodiscard]] execution_trace_ptr  get_original_trace() const { return original_trace; }

protected:

    bool  done() override;

private:
    execution_trace_ptr  original_trace;
    bool  similarity_only_for_uncovered_branchings;
};


}

#endif
