#include <fuzzing/typed_minimization_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <map>
#include <algorithm>

namespace  fuzzing {


template<typename T>
static T  get_random_value(random_generator_for_natural_32_bit&  generator)
{
    return (T)get_random_natural_32_bit_in_range(std::numeric_limits<T>::min(), std::numeric_limits<T>::max(), generator);
}


template<typename T>
static T  get_random_value(random_generator_for_natural_64_bit&  generator)
{
    return (T)get_random_natural_64_bit_in_range(std::numeric_limits<T>::min(), std::numeric_limits<T>::max(), generator);
}


template<typename T>
static float_64_bit  compute_max_variable_gradient_step(T const  v0, T const  v1, branching_function_value_type const  df)
{
    T const  dv = v1 - v0;
    T const  ev = dv * df < 0 ? std::numeric_limits<T>::max() : std::numeric_limits<T>::min();
    return (ev - v0) / ((float_64_bit)dv);
}


template<typename T>
static float_64_bit  compute_max_variable_gradient_step_float(T const  v0, T const  v1, branching_function_value_type const  df)
{
    T const  dv = v1 - v0;
    T const  ev = dv * df < 0 ? std::numeric_limits<T>::max() : -std::numeric_limits<T>::max();
    return (ev - v0) / ((float_64_bit)dv);
}


bool  typed_minimization_analysis::are_types_of_sensitive_bits_available(
        stdin_bits_and_types_pointer  bits_and_types,
        std::unordered_set<stdin_bit_index> const&  sensitive_bits
        )
{
    for (stdin_bit_index  idx : sensitive_bits)
        if (!is_known_type(bits_and_types->type_of_bit(idx)))
            return false;
    return !sensitive_bits.empty();
}


typed_minimization_analysis::typed_minimization_analysis()
    : state{ READY }
    , node{ nullptr }
    , bits_and_types{ nullptr }
    , execution_id{ 0 }
    , path{}
    , from_variables_to_input{}
    , types_of_variables{}
    , progress_stage{ SEED }
    , current_variable_values{}
    , current_fuction_value{}
    , partial_variable_values{}
    , partial_fuction_values{}
    , step_variable_indices{}
    , step_variable_values{}
    , step_fuction_values{}
    , executed_variable_values{}
    , stoped_early{ false }
    , random_generator32{}
    , random_generator64{}
    , statistics{}
{}


void  typed_minimization_analysis::start(
        branching_node* const  node_ptr,
        stdin_bits_and_types_pointer const  bits_and_types_ptr,
        natural_32_bit const  execution_id_
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && bits_and_types_ptr != nullptr);

    state = BUSY;
    node = node_ptr;
    bits_and_types = bits_and_types_ptr;
    execution_id = execution_id_;

    path.clear();
    for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
        path.push_back({ n->id, n->successor_direction(s) });
    std::reverse(path.begin(), path.end());

    std::map<natural_32_bit, std::pair<type_of_input_bits, std::vector<natural_8_bit> > >  start_bits_to_indices;
    for (stdin_bit_index  idx : node->sensitive_stdin_bits)
    {
        natural_32_bit const  type_index = bits_and_types->type_index(idx);
        natural_32_bit const  start_bit_idx = bits_and_types->type_start_bit_index(type_index);
        auto const  it_and_state = start_bits_to_indices.insert({ start_bit_idx, { bits_and_types->types.at(type_index), {} } });
        it_and_state.first->second.second.push_back(idx - start_bit_idx);
    }

    types_of_variables.clear();
    from_variables_to_input.clear();
    for (auto&  start_and_type_and_indices : start_bits_to_indices)
    {
        types_of_variables.push_back(start_and_type_and_indices.second.first);
        from_variables_to_input.push_back({ start_and_type_and_indices.first, {} });
        std::swap(from_variables_to_input.back().value_bit_indices, start_and_type_and_indices.second.second);
        std::sort(from_variables_to_input.back().value_bit_indices.begin(), from_variables_to_input.back().value_bit_indices.end());
    }

    progress_stage = SEED;
    current_variable_values.clear();
    current_fuction_value = INFINITY;
    partial_variable_values.clear();
    partial_fuction_values.clear();
    step_variable_indices.clear();
    step_variable_values.clear();
    step_fuction_values.clear();

    executed_variable_values.clear();

    stoped_early = false;

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, node->sensitive_stdin_bits.size());

    // recorder().on_typed_minimization_start(node, bit_translation, bits_and_types);
}


void  typed_minimization_analysis::stop()
{
    if (!is_busy())
        return;

    recorder().on_typed_minimization_stop();

    if (false)
    {
        stoped_early = true;

        ++statistics.stop_calls_early;
    }
    else
        ++statistics.stop_calls_regular;

    node->minimization_performed = true;
    node->minimization_start_execution = execution_id;

    state = READY;
}


bool  typed_minimization_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    switch (progress_stage)
    {
        case SEED:
            generate_next_seed();
            executed_variable_values = current_variable_values;
            ++statistics.seeds_processed;
            break;
        case PARTIALS:
            generate_next_partial();
            executed_variable_values = current_variable_values;
            executed_variable_values.at(partial_variable_values.size() - 1U) = partial_variable_values.back();
            break;
        case STEP:
            {
                INVARIANT(step_fuction_values.size() < step_variable_values.size());
                std::size_t const  idx = step_fuction_values.size();
                executed_variable_values = current_variable_values;
                executed_variable_values.at(step_variable_indices.at(idx)) = step_variable_values.at(idx);
            }
            break;
        default: { UNREACHABLE(); }
    }

    write_variable_values_to_input(bits_ref);

    ++statistics.generated_inputs;

    return true;
}


void  typed_minimization_analysis::process_execution_results(execution_trace_pointer const  trace_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr);

    branching_function_value_type const  function_value = process_execution_trace(trace_ptr);

    switch (progress_stage)
    {
        case SEED:
            if (std::isfinite(function_value))
            {
                current_fuction_value = function_value;
                progress_stage = PARTIALS;
                partial_variable_values.clear();
                partial_fuction_values.clear();
            }
            break;
        case PARTIALS:
            partial_fuction_values.push_back(function_value);
            if (partial_fuction_values.size() == types_of_variables.size())
            {
                compute_step_variables();
                if (step_variable_values.empty())
                    progress_stage = SEED;
                else
                {
                    progress_stage = STEP;
                    step_fuction_values.clear();
                    ++statistics.gradient_steps;
                }
            }
            break;
        case STEP:
            step_fuction_values.push_back(function_value);
            if (step_fuction_values.size() == step_variable_values.size())
            {
                compute_current_variable_and_function_value_from_step();
                if (std::isfinite(current_fuction_value))
                {
                    progress_stage = PARTIALS;
                    partial_variable_values.clear();
                    partial_fuction_values.clear();                
                }
                else
                    progress_stage = SEED;
            }
            break;
        default: { UNREACHABLE(); }
    }
}


void  typed_minimization_analysis::generate_next_seed()
{
    current_variable_values.clear();
    for (type_of_input_bits const  type : types_of_variables)
    {
        current_variable_values.push_back({});
        switch (type)
        {
            case type_of_input_bits::BOOLEAN:
                current_variable_values.back().value_boolean = get_random_natural_32_bit_in_range(1, 100, random_generator32) < 50;
                break;
            case type_of_input_bits::UINT8:
                current_variable_values.back().value_uint8 = get_random_value<natural_8_bit>(random_generator32);
                break;
            case type_of_input_bits::SINT8:
                current_variable_values.back().value_sint8 = get_random_value<integer_8_bit>(random_generator32);
                break;
            case type_of_input_bits::UINT16:
                current_variable_values.back().value_uint16 = get_random_value<natural_16_bit>(random_generator32);
                break;
            case type_of_input_bits::SINT16:
                current_variable_values.back().value_sint16 = get_random_value<integer_16_bit>(random_generator32);
                break;
            case type_of_input_bits::UINT32:
                current_variable_values.back().value_uint32 = get_random_value<natural_32_bit>(random_generator32);
                break;
            case type_of_input_bits::SINT32:
                current_variable_values.back().value_sint32 = get_random_value<integer_32_bit>(random_generator32);
                break;
            case type_of_input_bits::UINT64:
                current_variable_values.back().value_uint64 = get_random_value<natural_64_bit>(random_generator64);
                break;
            case type_of_input_bits::SINT64:
                current_variable_values.back().value_sint64 = get_random_value<integer_64_bit>(random_generator64);
                break;
            case type_of_input_bits::FLOAT32:
                current_variable_values.back().value_float32 = get_random_float_32_bit(random_generator32);
                break;
            case type_of_input_bits::FLOAT64:
                current_variable_values.back().value_float64 = get_random_float_64_bit(random_generator64);
                break;
            default: { UNREACHABLE(); }
        }
    }
}


void  typed_minimization_analysis::generate_next_partial()
{
    INVARIANT(partial_variable_values.size() < types_of_variables.size());
    partial_variable_values.push_back(current_variable_values.at(partial_variable_values.size()));
    switch (types_of_variables.at(partial_variable_values.size() - 1U))
    {
        case type_of_input_bits::BOOLEAN:
            partial_variable_values.back().value_boolean = !partial_variable_values.back().value_boolean;
            break;
        case type_of_input_bits::UINT8:
            partial_variable_values.back().value_uint8 += 1;
            break;
        case type_of_input_bits::SINT8:
            partial_variable_values.back().value_sint8 += 1;
            break;
        case type_of_input_bits::UINT16:
            partial_variable_values.back().value_uint16 += 1;
            break;
        case type_of_input_bits::SINT16:
            partial_variable_values.back().value_sint16 += 1;
            break;
        case type_of_input_bits::UINT32:
            partial_variable_values.back().value_uint32 += 1;
            break;
        case type_of_input_bits::SINT32:
            partial_variable_values.back().value_sint32 += 1;
            break;
        case type_of_input_bits::UINT64:
            partial_variable_values.back().value_uint64 += 1;
            break;
        case type_of_input_bits::SINT64:
            partial_variable_values.back().value_sint64 += 1;
            break;
        case type_of_input_bits::FLOAT32:
            partial_variable_values.back().value_float32 += 0.1f * std::fabs(partial_variable_values.back().value_float32);
            break;
        case type_of_input_bits::FLOAT64:
            partial_variable_values.back().value_float64 += 0.1f * std::fabs(partial_variable_values.back().value_float64);
            break;
        default: { UNREACHABLE(); }
    }
}


void  typed_minimization_analysis::compute_step_variables()
{
    step_variable_indices.clear();
    step_variable_values.clear();

    branching_function_value_type const  f0 = current_fuction_value;

    for (std::size_t  i = 0U; i != partial_fuction_values.size(); ++i)
    {
        branching_function_value_type const  f1 = partial_fuction_values.at(i);
        if (!std::isfinite(f1))
            continue;

        branching_function_value_type const  df = f1 - f0;
        if (std::fabs(df) < 1e-6)
            continue;

        float_64_bit const  max_t_f = -f0 / df;

        value_of_variable const&  var0 = current_variable_values.at(i);
        value_of_variable const&  var1 = partial_variable_values.at(i);

        float_64_bit  max_t_v = -1.0;

        switch (types_of_variables.at(i))
        {
            case type_of_input_bits::BOOLEAN:
                break;
            case type_of_input_bits::UINT8:
                max_t_v = compute_max_variable_gradient_step(var0.value_uint8, var1.value_uint8, df);
                break;
            case type_of_input_bits::SINT8:
                max_t_v = compute_max_variable_gradient_step(var0.value_sint8, var1.value_sint8, df);
                break;
            case type_of_input_bits::UINT16:
                max_t_v = compute_max_variable_gradient_step(var0.value_uint16, var1.value_uint16, df);
                break;
            case type_of_input_bits::SINT16:
                max_t_v = compute_max_variable_gradient_step(var0.value_sint16, var1.value_sint16, df);
                break;
            case type_of_input_bits::UINT32:
                max_t_v = compute_max_variable_gradient_step(var0.value_uint32, var1.value_uint32, df);
                break;
            case type_of_input_bits::SINT32:
                max_t_v = compute_max_variable_gradient_step(var0.value_sint32, var1.value_sint32, df);
                break;
            case type_of_input_bits::UINT64:
                max_t_v = compute_max_variable_gradient_step(var0.value_uint64, var1.value_uint64, df);
                break;
            case type_of_input_bits::SINT64:
                max_t_v = compute_max_variable_gradient_step(var0.value_sint64, var1.value_sint64, df);
                break;
            case type_of_input_bits::FLOAT32:
                max_t_v = compute_max_variable_gradient_step_float(var0.value_float32, var1.value_float32, df);
                break;
            case type_of_input_bits::FLOAT64:
                max_t_v = compute_max_variable_gradient_step_float(var0.value_float64, var1.value_float64, df);
                break;
            default: { UNREACHABLE(); }
        }

        float_64_bit  max_t = std::min(max_t_v, max_t_f);
        if (max_t > 0.0)
            for (float_64_bit const  t : {
                    max_t,
                    max_t * 0.75,
                    max_t * 0.50,
                    max_t * 0.25,
                    max_t * 0.10,
                    max_t * 0.01,
                    max_t * 0.001,
                    0.1,
                    0.01,
                    0.001
                    })
                if (t <= max_t)
                {
                    switch (types_of_variables.at(i))
                    {
                        case type_of_input_bits::UINT8: {
                            auto const old_value = var0.value_uint8;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::SINT8: {
                            auto const old_value = var0.value_sint8;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::UINT16: {
                            auto const old_value = var0.value_uint16;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::SINT16: {
                            auto const old_value = var0.value_sint16;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::UINT32: {
                            auto const old_value = var0.value_uint32;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::SINT32: {
                            auto const old_value = var0.value_sint32;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::UINT64: {
                            auto const old_value = var0.value_uint64;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::SINT64: {
                            auto const old_value = var0.value_sint64;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::FLOAT32: {
                            auto const old_value = var0.value_float32;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        case type_of_input_bits::FLOAT64: {
                            auto const old_value = var0.value_float64;
                            auto const new_value = old_value + (decltype(old_value))(t * df);
                            if (new_value != old_value)
                            {
                                step_fuction_values.push_back(new_value);
                                step_variable_indices.push_back(i);
                            }
                            } break;
                        default: { UNREACHABLE(); }
                    }
                }
    }
}


void  typed_minimization_analysis::compute_current_variable_and_function_value_from_step()
{
    natural_32_bit  best_variable_index{ std::numeric_limits<natural_32_bit>::max() };
    value_of_variable  best_variable_value{ .value_uint64 = 0ULL };
    branching_function_value_type  best_function_value{ current_fuction_value };

    for (std::size_t  i = 0U; i != partial_fuction_values.size(); ++i)
    {
        branching_function_value_type const  value = partial_fuction_values.at(i);
        if (!std::isfinite(value) && std::fabs(value) < std::fabs(best_function_value))
        {
            best_variable_index = i;
            best_variable_value = partial_variable_values.at(i);
            best_function_value = value;
        }
    }
    for (std::size_t  i = 0U; i != step_fuction_values.size(); ++i)
    {
        branching_function_value_type const  value = step_fuction_values.at(i);
        if (!std::isfinite(value) && std::fabs(value) < std::fabs(best_function_value))
        {
            best_variable_index = step_variable_indices.at(i);
            best_variable_value = step_variable_values.at(i);
            best_function_value = value;
        }
    }

    if (std::fabs(best_function_value) < std::fabs(current_fuction_value))
    {
        current_variable_values.at(best_variable_index) = best_variable_value;
        current_fuction_value = best_function_value;
    }
    else
        current_fuction_value = INFINITY;
}


void  typed_minimization_analysis::write_variable_values_to_input(vecb&  bits_ref)
{
    bits_ref = bits_and_types->bits;
    for (std::size_t  i = 0UL; i != from_variables_to_input.size(); ++i)
    {
        vecb  bits;
        natural_8_bit const* const  value_ptr = &executed_variable_values.at(i).value_uint8;
        bytes_to_bits(value_ptr, value_ptr + num_bytes(types_of_variables.at(i)), bits);

        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            bits_ref.at(mapping.input_start_bit_index + idx) = bits.at(idx);
    }
}


branching_function_value_type  typed_minimization_analysis::process_execution_trace(execution_trace_pointer  trace_ptr)
{
    auto  it = trace_ptr->begin();
    auto  it_path = path.begin();
    while (it != trace_ptr->end() && it_path != path.end() && it->id == it_path->first && it->direction == it_path->second)
    {
        ++it;
        ++it_path;
    }
    return it_path == path.end() && it != trace_ptr->end() && it->id == node->id && std::isnormal(it->value) ? it->value : INFINITY;
}


}
