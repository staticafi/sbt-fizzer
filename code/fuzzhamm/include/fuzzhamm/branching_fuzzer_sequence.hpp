#ifndef FUZZHAMM_BRANCHING_FUZZER_SEQUENCE_HPP_INCLUDED
#   define FUZZHAMM_BRANCHING_FUZZER_SEQUENCE_HPP_INCLUDED

#   include <fuzzhamm/branching_fuzzer_base.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <memory>

namespace  fuzzhamm {


struct  branching_fuzzer_sequence
{
    explicit branching_fuzzer_sequence(std::size_t  max_size_ = std::numeric_limits<std::size_t>::max());

    bool  push_back(branching_fuzzer_base_ptr  fuzzer);

    void  on_sample(vecb const&  input_stdin, coverage_distance_type  distance, bool  diverged);
    void  compute_input(vecb&  input_stdin);
    bool  done();

private:
    void  move_in_chain();

    std::vector<branching_fuzzer_base_ptr>  fuzzer_chain;
    std::size_t  active_fuzzer_index;
    std::size_t  max_size;
};


using  branching_fuzzer_sequence_ptr = std::shared_ptr<branching_fuzzer_sequence>;


}

#endif
