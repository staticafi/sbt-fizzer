#ifndef FUZZHAMM_BRANCHING_FUZZER_BASE_HPP_INCLUDED
#   define FUZZHAMM_BRANCHING_FUZZER_BASE_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <map>
#   include <unordered_map>
#   include <unordered_set>
#   include <memory>

namespace  fuzzhamm {


using namespace instrumentation;


struct  branching_fuzzer_base
{
    struct  sample_info
    {
        struct  numeric_representation
        {
            numeric_representation() = default;
            explicit numeric_representation(vecb const&  bits, bool  little_endian);
            natural_32_bit  natural;
            integer_32_bit  integer;
            float_32_bit    real;
        };

        sample_info() = default;
        explicit sample_info(vecb const&  bits, coverage_distance_type  distance_, bool  diverged_);
        vecb  bits;
        std::size_t  bits_hash;
        coverage_distance_type  distance;
        numeric_representation  endian_little;
        numeric_representation  endian_big;
        bool  diverged;
    };

    explicit  branching_fuzzer_base(
            std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
            vecb const&  input_stdin,
            coverage_distance_type  distance,
            std::unordered_set<natural_16_bit> const&  escape_stdin_bits_
            );
    virtual  ~branching_fuzzer_base() = default;

    void  on_sample(vecb const&  input_stdin, coverage_distance_type  distance, bool  diverged);
    void  compute_input(vecb&  input_stdin);
    virtual bool  done();

    [[nodiscard]] std::size_t  num_bits() const { return bit_translation.size(); }
    random_generator_for_natural_32_bit&  generator_ref() { return generator; }
    [[nodiscard]] natural_32_bit  num_generated_inputs() const { return num_inputs_generated; }
    [[nodiscard]] sample_info const&  get_root_sample() const { return root_sample; }
    [[nodiscard]] sample_info const&  get_last_sample() const { return last_sample; }
    [[nodiscard]] std::unordered_set<natural_16_bit> const&  escape_bit_indices() const { return escape_stdin_bits; }

protected:

    virtual void  update();
    virtual void  find_minimum(vecb&  input);

private:
    void  translate_from_input(vecb const&  input_stdin, vecb&  bits) const;
    void  translate_to_input(vecb const&  bits, vecb&  input_stdin) const;

    vecb  trace_input_stdin;
    vecu16 bit_translation;
    std::unordered_set<natural_16_bit>  escape_stdin_bits;
    random_generator_for_natural_32_bit   generator;
    sample_info  root_sample;
    sample_info  last_sample;
    natural_32_bit  num_inputs_generated;
};


using  branching_fuzzer_base_ptr = std::shared_ptr<branching_fuzzer_base>;


}

#endif
