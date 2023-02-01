#ifndef FUZZHAMM_BRANCHING_FUZZER_EXTENDED_DESCENT_HPP_INCLUDED
#   define FUZZHAMM_BRANCHING_FUZZER_EXTENDED_DESCENT_HPP_INCLUDED

#   include <fuzzhamm/branching_fuzzer_base.hpp>

namespace  fuzzhamm {


struct  branching_fuzzer_extended_descent : public branching_fuzzer_base
{
    branching_fuzzer_extended_descent(
            std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
            vecb const&  input_stdin,
            coverage_distance_type  distance,
            std::unordered_set<natural_16_bit> const&  escape_stdin_bits
            );

    branching_fuzzer_extended_descent(
            std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
            vecb const&  input_stdin,
            std::unordered_set<natural_16_bit> const&  escape_stdin_bits
            );

    bool  done() override;

protected:
    void update() override;
    void find_minimum(vecb&  input) override;

private:
    enum STAGE {
        NEW_SAMPLE,
        PARTIALS,
        PARTIALS_EXTENDED,
        END
    } stage;
    vecf64 bit_max_changes;
    vecu16 bit_order;
    vecb  sample;
    coverage_distance_type  distance;
    vecf64 partials;
    vecf64 partials_extended;
};


}

#endif
