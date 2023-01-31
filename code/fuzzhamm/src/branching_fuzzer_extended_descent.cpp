#include <fuzzhamm/branching_fuzzer_extended_descent.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


branching_fuzzer_extended_descent::branching_fuzzer_extended_descent(
        std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
        vecb const&  input_stdin,
        coverage_distance_type  distance,
        std::unordered_set<natural_16_bit> const&  escape_stdin_bits
        )
    : branching_fuzzer_base(sensitive_stdin_bits, input_stdin, distance, escape_stdin_bits)
    , stage(PARTIALS)
    , bit_max_changes(num_bits(), 0.0)
    , bit_order()
    , sample(get_root_sample().bits)
    , distance(get_root_sample().distance)
    , partials()
    , partials_extended()
{
    bit_order.reserve(num_bits());
    partials.reserve(num_bits());
    partials_extended.reserve(num_bits() - 1UL);
}


branching_fuzzer_extended_descent::branching_fuzzer_extended_descent(
        std::unordered_set<natural_16_bit> const&  sensitive_stdin_bits,
        vecb const&  input_stdin,
        std::unordered_set<natural_16_bit> const&  escape_stdin_bits
        )
    : branching_fuzzer_base(sensitive_stdin_bits, input_stdin, std::numeric_limits<coverage_distance_type>::max(), escape_stdin_bits)
    , stage(NEW_SAMPLE)
    , bit_max_changes(num_bits(), 0.0)
    , bit_order()
    , sample(get_root_sample().bits)
    , distance()
    , partials()
    , partials_extended()
{
    bit_order.reserve(num_bits());
    partials.reserve(num_bits());
    partials_extended.reserve(num_bits() - 1UL);
}


bool  branching_fuzzer_extended_descent::done()
{
    return stage == END;
}


void branching_fuzzer_extended_descent::update()
{
    if (stage == NEW_SAMPLE)
    {
        stage = PARTIALS;
        sample = get_last_sample().bits;
        distance = get_last_sample().distance;
        partials.clear();
        partials_extended.clear();
    }
    else if (stage == PARTIALS)
    {
        coverage_distance_type const  abs_delta = std::fabs(get_last_sample().distance - distance);
        if (abs_delta > bit_max_changes.at(partials.size()))
        {
            bit_max_changes.at(partials.size()) = abs_delta;
            bit_order.clear();
        }
        partials.push_back(get_last_sample().distance);
    }
    else if (stage == PARTIALS_EXTENDED)
    {
        partials_extended.push_back(get_last_sample().distance);
    }
    else if (stage == END)
    {
        // Nothing to do.
    }
    else
        UNREACHABLE();
}


void branching_fuzzer_extended_descent::find_minimum(vecb&  input)
{
    if (stage == NEW_SAMPLE)
    {
        input = sample;
    }
    else if (stage == PARTIALS)
    {
        if (partials.size() < num_bits())
        {
            input = sample;
            input.at(partials.size()) = !input.at(partials.size());
        }
        else
        {
            // TODO: Bits we are fuzzing here may affect other branchings
            //       appearing before this one in the trace. So, if there
            //       is more than one partial improving the coverage distance,
            //       then the choice should consider also coverage change
            //       of other affected branchings. Namely, we should choose
            //       the partial minimizing the distance of the current
            //       branching and maximazing the distance of the other
            //       affected branchings.
            std::size_t  idx = arg_inf(partials);
            if (partials.at(idx) < distance)
            {
                input = sample;
                input.at(idx) = !input.at(idx);
                stage = NEW_SAMPLE;
            }
            else
            {
                stage = PARTIALS_EXTENDED;
                find_minimum(input);
            }
        }
    }
    else if (stage == PARTIALS_EXTENDED)
    {
        if (bit_order.empty())
        {
            std::multimap<coverage_distance_type, natural_16_bit> sorted_bit_max_changes;
            for (std::size_t  i = 0UL; i != num_bits(); ++i)
                sorted_bit_max_changes.insert({ at(bit_max_changes,i), (natural_16_bit)i });
            for (auto it = sorted_bit_max_changes.rbegin(); it != sorted_bit_max_changes.rend(); ++it)
                bit_order.push_back(it->second);
        }
        if (partials_extended.empty() || partials_extended.size() < num_bits() - 1UL)
        {
            input = sample;
            for (std::size_t  i = partials_extended.size(); i != num_bits(); ++i)
            {
                natural_16_bit const  k = at(bit_order, i);
                input.at(k) = !input.at(k);
            }
        }
        else
        {
            std::size_t  idx = arg_inf(partials_extended);
            if (partials_extended.at(idx) < distance)
            {
                input = sample;
                for (std::size_t  i = idx; i != num_bits(); ++i)
                {
                    natural_16_bit const  k = at(bit_order, i);
                    input.at(k) = !input.at(k);
                }
                stage = NEW_SAMPLE;
            }
            else
            {
                branching_fuzzer_base::find_minimum(input);
                stage = END;
            }
        }
    }
    else
        UNREACHABLE();
}


}
