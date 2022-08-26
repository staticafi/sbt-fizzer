#include <fuzzhamm/execution_trace_utils.hpp>
#include <fuzzhamm/sensitivity_fuzzer_hamming.hpp>
#include <fuzzhamm/sensitivity_fuzzer_progress_check.hpp>
#include <fuzzhamm/branching_fuzzer_extended_descent.hpp>
#include <fuzzhamm/iid_fuzzer_improve_branching_directions.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_base_ptr  create_sensitivity_fuzzer(execution_trace_ptr const  the_trace, bool const  similarity_only_for_uncovered_branchings)
{
    sensitivity_fuzzer_sequence_ptr const  fuzzer_sequence_ptr = std::make_shared<sensitivity_fuzzer_sequence>(
            the_trace,
            [](std::size_t const  num_trials) { return 2UL + 3UL * num_trials; }(2UL)
            );
    fuzzer_sequence_ptr->push_back(
            std::make_shared<sensitivity_fuzzer_hamming>(the_trace, 1U, fuzzer_sequence_ptr)
            );
    fuzzer_sequence_ptr->push_back(
            std::make_shared<sensitivity_fuzzer_progress_check>(the_trace, the_trace, fuzzer_sequence_ptr, similarity_only_for_uncovered_branchings)
            );
    return fuzzer_sequence_ptr;
}


branching_fuzzer_sequence_ptr  create_branching_fuzzer_sequence(
        execution_trace_record const&  rec,
        vecb const&  input_stdin,
        random_generator_for_natural_32_bit&  random_generator
        )
{
    branching_fuzzer_sequence_ptr const  fuzzer = std::make_shared<branching_fuzzer_sequence>();

    std::vector<std::unordered_set<natural_16_bit> const*>  vector_of_sensitive_bits_sets;
    std::unordered_set<natural_16_bit> all_sensitive_stdin_bits;
    if (2ULL * rec.diverged_stdin_bits.size() < rec.sensitive_stdin_bits.size())
    {
        all_sensitive_stdin_bits.insert(rec.sensitive_stdin_bits.begin(), rec.sensitive_stdin_bits.end());
        all_sensitive_stdin_bits.insert(rec.diverged_stdin_bits.begin(), rec.diverged_stdin_bits.end());
        vector_of_sensitive_bits_sets.push_back(&all_sensitive_stdin_bits);
    }
    else
    {
        vector_of_sensitive_bits_sets.push_back(&rec.sensitive_stdin_bits);
        vector_of_sensitive_bits_sets.push_back(&rec.diverged_stdin_bits);
    }
    std::unordered_set<natural_16_bit>  sensitive_stdin_bits;
    for (auto const&  sensitive_bits_set : vector_of_sensitive_bits_sets)
    {
        std::size_t const  old_size = sensitive_stdin_bits.size();
        sensitive_stdin_bits.insert(sensitive_bits_set->begin(), sensitive_bits_set->end());
        if (old_size < sensitive_stdin_bits.size())
        {
            std::size_t const  num_bits = std::min(sensitive_stdin_bits.size(), (size_t) 64);
            vecu64  class_counts;
            sample_counts_per_hamming_class(class_counts, num_bits, num_bits * num_bits);
            for (std::size_t hamming_class = 0UL; hamming_class != class_counts.size(); ++hamming_class)
            {
                vec<vecb>  sensitive_bits_samples;
                generate_samples_of_hamming_class(
                        sensitive_bits_samples,
                        sensitive_stdin_bits.size(),
                        hamming_class,
                        class_counts.at(hamming_class),
                        random_generator
                        );
                for (vecb const&  sensitive_bits_sample : sensitive_bits_samples)
                {
                    vecb  sample = input_stdin;
                    {
                        std::size_t  i = 0ULL;
                        auto  it = sensitive_stdin_bits.begin();
                        while (it != sensitive_stdin_bits.end())
                        {
                            sample.at(*it) = sensitive_bits_sample.at(i);
                            ++i;
                            ++it;
                        }
                    }
                    fuzzer->push_back(std::make_shared<branching_fuzzer_extended_descent>(
                            sensitive_stdin_bits,
                            sample,
                            std::unordered_set<natural_16_bit>{}
                            ));
                }
            }
        }
    }

    return  fuzzer;
}


iid_fuzzer_base_ptr  create_iid_fuzzer(location_id const  loc_id)
{
    return std::make_shared<iid_fuzzer_improve_branching_directions>(loc_id);
}


}
