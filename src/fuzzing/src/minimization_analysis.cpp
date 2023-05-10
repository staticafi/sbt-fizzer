#include <fuzzing/minimization_analysis.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <map>
#include <algorithm>

namespace  fuzzing {


void  minimization_analysis::start(branching_node* const  node_ptr, stdin_bits_pointer const  bits_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && bits_ptr != nullptr);

    state = BUSY;
    node = node_ptr;
    bits = bits_ptr;

    path.clear();
    for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
        path.push_back({ n->id, n->successor_direction(s) });
    std::reverse(path.begin(), path.end());

    bit_translation.assign(node->sensitive_stdin_bits.begin(), node->sensitive_stdin_bits.end());
    std::sort(bit_translation.begin(), bit_translation.end());

    std::size_t  total_samples;
    {
        // std::size_t const  bits_width = std::min(bit_translation.size(), (std::size_t)64ULL);
        // total_samples = bits_width * bits_width;
        total_samples = bit_translation.size();
    }

    seeds.clear();
    vecu64  class_counts;
    sample_counts_per_hamming_class(class_counts, bit_translation.size(), total_samples);
    for (std::size_t hamming_class = 0UL; hamming_class != class_counts.size(); ++hamming_class)
        generate_samples_of_hamming_class(
                seeds,
                bit_translation.size(),
                hamming_class,
                class_counts.at(hamming_class),
                random_generator
                );
    std::reverse(seeds.begin(), seeds.end());

    stoped_early = false;
    descent = {};

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, bit_translation.size());
}


void  minimization_analysis::stop()
{
    if (!is_busy())
        return;

    if (!seeds.empty() || descent.stage != gradient_descent_state::TAKE_NEXT_SEED)
    {
        stoped_early = true;

        ++statistics.stop_calls_early;
    }
    else
        ++statistics.stop_calls_regular;

    node->minimization_disabled = true;

    state = READY;
}


bool  minimization_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    vecb  computed_input_stdin;

    while (true)
    {
        if (descent.stage == gradient_descent_state::TAKE_NEXT_SEED)
        {
            if (seeds.empty())
            {
                stop();
                return false;
            }

            INVARIANT(seeds.back().size() == bit_translation.size());

            descent.stage = gradient_descent_state::EXECUTE_SEED;
            descent.bits = seeds.back();
            descent.value = std::numeric_limits<branching_function_value_type>::max();
            descent.partials.clear();
            descent.partials_extended.clear();
            descent.bit_max_changes.assign(bit_translation.size(), 0.0);
            descent.bit_order.clear();

            computed_input_stdin = descent.bits;

            seeds.pop_back();

            ++statistics.seeds_processed;

            break;
        }
        else if (descent.stage == gradient_descent_state::EXECUTE_SEED)
        {
            descent.stage = gradient_descent_state::PARTIALS;
        }
        else if (descent.stage == gradient_descent_state::STEP)
        {
            descent.stage = gradient_descent_state::PARTIALS;
            descent.partials.clear();
            descent.partials_extended.clear();

            ++statistics.gradient_steps;
        }
        else if (descent.stage == gradient_descent_state::PARTIALS)
        {
            if (descent.partials.size() < bit_translation.size())
            {
                computed_input_stdin = descent.bits;
                computed_input_stdin.at(descent.partials.size()) = !computed_input_stdin.at(descent.partials.size());
                break;
            }
            else
            {
                std::size_t  idx = arg_inf(descent.partials);
                if (descent.partials.at(idx) < descent.value)
                {
                    descent.bits.at(idx) = !descent.bits.at(idx);
                    descent.value = descent.partials.at(idx);
                    descent.stage = gradient_descent_state::STEP;
                }
                else if (bit_translation.size() > 1ULL)
                    descent.stage = gradient_descent_state::PARTIALS_EXTENDED;
                else
                    descent.stage = gradient_descent_state::TAKE_NEXT_SEED;
            }
        }
        else if (descent.stage == gradient_descent_state::PARTIALS_EXTENDED)
        {
            if (descent.bit_order.empty())
            {
                std::multimap<branching_function_value_type, natural_16_bit> sorted_bit_max_changes;
                for (std::size_t  i = 0UL; i != bit_translation.size(); ++i)
                    sorted_bit_max_changes.insert({ at(descent.bit_max_changes,i), (natural_16_bit)i });
                for (auto it = sorted_bit_max_changes.rbegin(); it != sorted_bit_max_changes.rend(); ++it)
                    descent.bit_order.push_back(it->second);
            }
            if (descent.partials_extended.size() < bit_translation.size() - 1UL)
            {
                computed_input_stdin = descent.bits;
                for (std::size_t  i = descent.partials_extended.size(); i != bit_translation.size(); ++i)
                {
                    natural_16_bit const  k = at(descent.bit_order, i);
                    computed_input_stdin.at(k) = !computed_input_stdin.at(k);
                }
                break;
            }
            else
            {
                std::size_t  idx = arg_inf(descent.partials_extended);
                if (descent.partials_extended.at(idx) < descent.value)
                {
                    for (std::size_t  i = idx; i != bit_translation.size(); ++i)
                    {
                        natural_16_bit const  k = at(descent.bit_order, i);
                        descent.bits.at(k) = !descent.bits.at(k);
                    }
                    descent.value = descent.partials_extended.at(idx);
                    descent.stage = gradient_descent_state::STEP;
                }
                else
                    descent.stage = gradient_descent_state::TAKE_NEXT_SEED;
            }
        }
        else { UNREACHABLE(); }
    }

    bits_ref = *bits;
    for (std::size_t  i = 0UL; i != bit_translation.size(); ++i)
        bits_ref.at(bit_translation.at(i)) = computed_input_stdin.at(i);

    ++statistics.generated_inputs;

    return true;
}


void  minimization_analysis::process_execution_results(execution_trace_pointer const  trace_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr);

    branching_function_value_type  last_stdin_value;
    {
        last_stdin_value = std::numeric_limits<branching_function_value_type>::max();
        auto  it = trace_ptr->begin();
        auto  it_path = path.begin();
        while (it != trace_ptr->end() && it_path != path.end() && it->id == it_path->first && it->direction == it_path->second)
        {
            ++it;
            ++it_path;
        }
        if (it_path == path.end() && it != trace_ptr->end() && it->id == node->id)
            last_stdin_value = std::fabs(it->value);
    }

    if (descent.stage == gradient_descent_state::EXECUTE_SEED)
    {
        descent.value = last_stdin_value;
    }
    else if (descent.stage == gradient_descent_state::PARTIALS)
    {
        branching_function_value_type const  abs_delta = std::fabs(last_stdin_value - descent.value);
        if (abs_delta > descent.bit_max_changes.at(descent.partials.size()))
        {
            descent.bit_max_changes.at(descent.partials.size()) = abs_delta;
            descent.bit_order.clear();
        }
        descent.partials.push_back(last_stdin_value);
    }
    else if (descent.stage == gradient_descent_state::PARTIALS_EXTENDED)
    {
        descent.partials_extended.push_back(last_stdin_value);
    }
    else { UNREACHABLE(); }
}


}
