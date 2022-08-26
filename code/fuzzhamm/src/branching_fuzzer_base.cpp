#include <fuzzhamm/branching_fuzzer_base.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


branching_fuzzer_base::sample_info::numeric_representation::numeric_representation(
        vecb const&  bits,
        bool const little_endian
        )
    : natural(0U)
    , integer(0)
    , real(0.0f)
{
    copy_bits_to_bytes_array((natural_8_bit*)&natural, sizeof(natural_32_bit), false, bits, little_endian);
    copy_bits_to_bytes_array((natural_8_bit*)&integer, sizeof(integer_32_bit), true, bits, little_endian);
    *(natural_32_bit*)&real = natural;
}


branching_fuzzer_base::sample_info::sample_info(vecb const&  bits_, coverage_distance_type const distance_, bool const  diverged_)
    : bits(bits_)
    , bits_hash(make_hash(bits_))
    , distance(distance_)
    , endian_little(bits, true)
    , endian_big(bits, false)
    , diverged(diverged_)
{}


branching_fuzzer_base::branching_fuzzer_base(
        std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
        vecb const&  input_stdin,
        coverage_distance_type  distance,
        std::unordered_set<natural_16_bit> const&  escape_stdin_bits_
        )
    : trace_input_stdin(input_stdin)
    , bit_translation(sensitive_stdin_bits.begin(), sensitive_stdin_bits.end())
    , escape_stdin_bits()
    , generator(0U)
    , root_sample()
    , last_sample()
    , num_inputs_generated(0U)
{
    std::sort(bit_translation.begin(), bit_translation.end());

    for (natural_16_bit  i = 0U; i != (natural_16_bit)bit_translation.size(); ++i)
        if (escape_stdin_bits_.count(bit_translation.at(i)) != 0UL)
            escape_stdin_bits.insert(i);

    vecb input(num_bits(), false);
    translate_from_input(trace_input_stdin, input);
    root_sample = sample_info{input, distance, false};
    last_sample = root_sample;
}

void  branching_fuzzer_base::on_sample(vecb const&  input_stdin, coverage_distance_type  distance, bool const  diverged)
{
    vecb input(num_bits(), false);
    translate_from_input(input_stdin, input);
    last_sample = sample_info{input, distance, diverged};
    update();
}

void  branching_fuzzer_base::compute_input(vecb&  input_stdin)
{
    vecb input(num_bits(), false);
    find_minimum(input);
    input_stdin = trace_input_stdin;
    translate_to_input(input, input_stdin);
    ++num_inputs_generated;
}


bool  branching_fuzzer_base::done()
{
    return false;
}


void  branching_fuzzer_base::update()
{
    // nothing to do here.
}


void  branching_fuzzer_base::find_minimum(vecb&  input)
{
    for (std::size_t  i = 0UL; i != num_bits(); ++i)
        input.at(i) = (natural_8_bit)get_random_natural_32_bit_in_range(0U, 255U, generator_ref()) < 128U;
}


void  branching_fuzzer_base::translate_from_input(vecb const&  input_stdin, vecb&  bits) const
{
    for (std::size_t  i = 0UL; i != num_bits(); ++i)
        bits.at(i) = input_stdin.at(bit_translation.at(i));
}


void  branching_fuzzer_base::translate_to_input(vecb const&  bits, vecb&  input_stdin) const
{
    for (std::size_t  i = 0UL; i != num_bits(); ++i)
        input_stdin.at(bit_translation.at(i)) = bits.at(i);
}


}
