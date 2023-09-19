#include <fuzzing/sensitivity_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


sensitivity_analysis::sensitivity_analysis()
    : state{ READY }
    , bits_and_types{ nullptr }
    , trace{ nullptr }
    , mutated_bit_index{ 0 }
    , mutated_type_index{ 0 }
    , mutated_value_index{ 0 }
    , probed_bit_start_index{ 0 }
    , probed_bit_end_index{ 0 }
    , node{ nullptr }
    , execution_id{ 0 }
    , changed_nodes{}
    , stopped_early{ false }
    , statistics{}
{}


bool  sensitivity_analysis::is_mutated_bit_index_valid() const
{
    return mutated_bit_index < node->get_num_stdin_bits();
}


bool  sensitivity_analysis::is_mutated_type_index_valid() const
{
    return mutated_type_index < node->best_stdin->types.size() &&
                node->best_stdin->type_end_bit_index(mutated_type_index) < node->get_num_stdin_bits();
}


void  sensitivity_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && node_ptr->best_stdin && node_ptr->best_trace != nullptr);
    ASSUMPTION(node_ptr->best_trace->size() > node_ptr->get_trace_index());
    ASSUMPTION(
        [node_ptr]() -> bool {
            branching_node*  n = node_ptr;
            for (trace_index_type  i = n->get_trace_index() + 1U; i > 0U; --i, n = n->predecessor)
            {
                if (n == nullptr || n->id != node_ptr->best_trace->at(i - 1U).id)
                    return false;
                if (i > 1U && n->predecessor->successor_direction(n) != node_ptr->best_trace->at(i - 2U).direction)
                    return false;
            }
            return n == nullptr;
        }()
        );

    state = BUSY;
    bits_and_types = node_ptr->best_stdin;
    trace = node_ptr->best_trace;
    mutated_bit_index = 0;
    mutated_type_index = 0;
    mutated_value_index = 0;
    node = node_ptr;
    execution_id = execution_id_;
    changed_nodes.clear();
    stopped_early = false;

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, (std::size_t)node->get_num_stdin_bits());

    recorder().on_sensitivity_start(node);
}


void  sensitivity_analysis::stop()
{
    if (!is_busy())
        return;

    if (is_mutated_bit_index_valid() || is_mutated_type_index_valid())
    {
        stopped_early = true;

        recorder().on_sensitivity_stop(progress_recorder::EARLY);

        ++statistics.stop_calls_early;
    }
    else
    {
        recorder().on_sensitivity_stop(progress_recorder::REGULAR);

        ++statistics.stop_calls_regular;
    }

    state = READY;
}


bool  sensitivity_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (is_mutated_bit_index_valid())
    {
        bits_ref = bits_and_types->bits;
        bits_ref.at(mutated_bit_index) = !bits_ref.at(mutated_bit_index);

        probed_bit_start_index = 8 * (mutated_bit_index / 8);
        probed_bit_end_index = probed_bit_start_index + 8;

        ++mutated_bit_index;
    }
    else if (!generate_next_typed_value(bits_ref))
    {
        for (branching_node* n = node; n != nullptr; n = n->predecessor)
        {
            if (!n->sensitivity_performed)
                changed_nodes.insert(n);
            n->sensitivity_performed = true;
            n->sensitivity_start_execution = execution_id;
        }

        stop();
        return false;
    }

    ++statistics.generated_inputs;

    return true;
}


template<typename T, int N>
bool  sensitivity_analysis::write_bits(vecb&  bits_ref, T const  (&values)[N])
{
    if (mutated_value_index >= N)
    {
        mutated_value_index = 0U;
        return false;
    }

    probed_bit_start_index = node->best_stdin->type_start_bit_index(mutated_type_index);
    probed_bit_end_index = probed_bit_start_index + 8 * sizeof(T);

    vecb  bits;
    natural_8_bit const* const  value_ptr = (natural_8_bit const*)&values[mutated_value_index];
    bytes_to_bits(value_ptr, value_ptr + sizeof(T), bits);

    bits_ref = bits_and_types->bits;
    std::copy(bits.begin(), bits.end(), std::next(bits_ref.begin(), probed_bit_start_index));

    ++mutated_value_index;
    return true;
}


bool  sensitivity_analysis::generate_next_typed_value(vecb&  bits_ref)
{
    for ( ; is_mutated_type_index_valid(); ++mutated_type_index)
        switch (node->best_stdin->types.at(mutated_type_index))
        {
        case type_of_input_bits::BOOLEAN:
            break;

        case type_of_input_bits::SINT8:
            {
                static integer_8_bit const  values[] = {
                        std::numeric_limits<integer_8_bit>::min(),
                        std::numeric_limits<integer_8_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;
        case type_of_input_bits::UINT8:
        case type_of_input_bits::UNTYPED8:
            {
                static natural_8_bit const  values[] = {
                        std::numeric_limits<natural_8_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;

        case type_of_input_bits::SINT16:
            {
                static integer_16_bit const  values[] = {
                        std::numeric_limits<integer_16_bit>::min(),
                        std::numeric_limits<integer_16_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;
        case type_of_input_bits::UINT16:
        case type_of_input_bits::UNTYPED16:
            {
                static natural_16_bit const  values[] = {
                        std::numeric_limits<natural_16_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;

        case type_of_input_bits::SINT32:
            {
                static integer_32_bit const  values[] = {
                        std::numeric_limits<integer_32_bit>::min(),
                        std::numeric_limits<integer_32_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;
        case type_of_input_bits::UINT32:
        case type_of_input_bits::UNTYPED32:
            {
                static natural_32_bit const  values[] = {
                        std::numeric_limits<natural_32_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;

        case type_of_input_bits::SINT64:
            {
                static integer_64_bit const  values[] = {
                        std::numeric_limits<integer_64_bit>::min(),
                        std::numeric_limits<integer_64_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;
        case type_of_input_bits::UINT64:
        case type_of_input_bits::UNTYPED64:
            {
                static natural_64_bit const  values[] = {
                        std::numeric_limits<natural_64_bit>::max(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;

        case type_of_input_bits::FLOAT32:
            {
                static float_32_bit const  values[] = {
                        -std::numeric_limits<float_32_bit>::infinity(),
                        std::numeric_limits<float_32_bit>::lowest(),
                        -std::numeric_limits<float_32_bit>::min(),
                        -std::numeric_limits<float_32_bit>::epsilon(),
                        std::numeric_limits<float_32_bit>::epsilon(),
                        std::numeric_limits<float_32_bit>::min(),
                        std::numeric_limits<float_32_bit>::max(),
                        std::numeric_limits<float_32_bit>::infinity(),
                        std::numeric_limits<float_32_bit>::quiet_NaN(),
                        std::numeric_limits<float_32_bit>::signaling_NaN(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;
        case type_of_input_bits::FLOAT64:
            {
                static float_64_bit const  values[] = {
                        -std::numeric_limits<float_64_bit>::infinity(),
                        std::numeric_limits<float_64_bit>::lowest(),
                        -std::numeric_limits<float_64_bit>::min(),
                        -std::numeric_limits<float_64_bit>::epsilon(),
                        std::numeric_limits<float_64_bit>::epsilon(),
                        std::numeric_limits<float_64_bit>::min(),
                        std::numeric_limits<float_64_bit>::max(),
                        std::numeric_limits<float_64_bit>::infinity(),
                        std::numeric_limits<float_64_bit>::quiet_NaN(),
                        std::numeric_limits<float_64_bit>::signaling_NaN(),
                        };
                if (write_bits(bits_ref, values))
                    return true;
            }
            break;

        default:
            UNREACHABLE();
            break;
        }
    return false;
}



void  sensitivity_analysis::process_execution_results(execution_trace_pointer const  trace_ptr, branching_node* const  entry_branching_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr && entry_branching_ptr != nullptr);

    branching_node*  n = entry_branching_ptr;
    for (trace_index_type  i = 0U, end = std::min(node->get_trace_index() + 1U, (trace_index_type)trace_ptr->size()); i < end; ++i)
    {
        branching_coverage_info const&  info_orig = trace->at(i);
        branching_coverage_info const&  info_curr = trace_ptr->at(i);

        INVARIANT(info_orig.id == info_curr.id && info_orig.id == n->id);

        if (info_orig.value != info_curr.value)
            for (stdin_bit_index i = probed_bit_start_index; i != probed_bit_end_index; ++i)
            {
                auto const  it_and_state = n->sensitive_stdin_bits.insert(i);
                if (it_and_state.second)
                    changed_nodes.insert(n);
            }

        if (info_orig.direction != info_curr.direction)
            break;        
        n = n->successor(info_orig.direction).pointer;
    }
}


}
