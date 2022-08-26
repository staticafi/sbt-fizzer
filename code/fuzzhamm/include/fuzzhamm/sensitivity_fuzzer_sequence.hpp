#ifndef FUZZHAMM_SENSITIVITY_FUZZER_SEQUENCE_HPP_INCLUDED
#   define FUZZHAMM_SENSITIVITY_FUZZER_SEQUENCE_HPP_INCLUDED

#   include <fuzzhamm/sensitivity_fuzzer_base.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <memory>

namespace  fuzzhamm {


struct  sensitivity_fuzzer_sequence : public sensitivity_fuzzer_base
{
    explicit sensitivity_fuzzer_sequence(execution_trace_ptr  the_trace, std::size_t  max_size_, sensitivity_fuzzer_base_ptr  parent = nullptr);

    bool  push_back(sensitivity_fuzzer_base_ptr  fuzzer);

protected:

    void  update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index) override;
    void  mutate(vecb&  input_stdin) override;
    bool  done() override;

private:
    void  move_in_chain();

    std::vector<sensitivity_fuzzer_base_ptr>  fuzzer_chain;
    std::size_t  active_fuzzer_index;
    std::size_t  max_size;
};


using  sensitivity_fuzzer_sequence_ptr = std::shared_ptr<sensitivity_fuzzer_sequence>;


}

#endif
