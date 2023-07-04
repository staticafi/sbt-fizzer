#include <fuzzing/typed_minimization_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <map>
#include <algorithm>

namespace  fuzzing {


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
    , current_function_value{}
    , partial_variable_values{}
    , partial_function_values{}
    , gradient{}
    , gradient_direction_locks{}
    , step_variable_values{}
    , step_function_values{}
    , executed_variable_values{}
    , hashes_of_generated_bits{}
    , num_fast_and_genuine_executions{ 0U }
    , stopped_early{ false }
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

    INVARIANT(!types_of_variables.empty());

    progress_stage = SEED;
    current_variable_values.clear();
    current_function_value = INFINITY;
    partial_variable_values.clear();
    partial_function_values.clear();
    gradient.clear();
    gradient_direction_locks.clear();
    step_variable_values.clear();
    step_function_values.clear();

    executed_variable_values.clear();
    hashes_of_generated_bits.clear();

    num_fast_and_genuine_executions = 0U;
    stopped_early = false;

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, node->sensitive_stdin_bits.size());

    // recorder().on_typed_minimization_start(node, bit_translation, bits_and_types);
}


void  typed_minimization_analysis::stop()
{
    if (!is_busy())
        return;

    recorder().on_typed_minimization_stop();

    if (num_fast_and_genuine_executions < max_num_executions())
    {
        stopped_early = true;

        ++statistics.stop_calls_early;
    }
    else
        ++statistics.stop_calls_regular;

    node->minimization_performed = true;
    node->minimization_start_execution = execution_id;

    state = READY;
}


natural_32_bit  typed_minimization_analysis::max_num_executions() const
{
    return (natural_32_bit)(100U * node->sensitive_stdin_bits.size());
}


bool  typed_minimization_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    do
    {
        if (num_fast_and_genuine_executions >= max_num_executions())
        {
            stop();
            return false;
        }

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
                INVARIANT(step_function_values.size() < step_variable_values.size());
                executed_variable_values = step_variable_values.at(step_function_values.size());
                ++statistics.gradient_samples;
                break;
            default: { UNREACHABLE(); }
        }

        ++num_fast_and_genuine_executions;
    }
    while (apply_fast_execution_using_cache());

    bits_ref = bits_and_types->bits;
    collect_bits_of_executed_variable_values([&bits_ref](natural_32_bit const  idx, bool const  state) { bits_ref.at(idx) = state; });

    ++statistics.generated_inputs;

    return true;
}


void  typed_minimization_analysis::process_execution_results(execution_trace_pointer const  trace_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr);

    auto  it = trace_ptr->begin();
    auto  it_path = path.begin();
    while (it != trace_ptr->end() && it_path != path.end() && it->id == it_path->first && it->direction == it_path->second)
    {
        ++it;
        ++it_path;
    }
    branching_function_value_type const  function_value =
            it_path == path.end() && it != trace_ptr->end() && it->id == node->id && std::isfinite(it->value) ? it->value : INFINITY;

    hashes_of_generated_bits.insert({ executed_variable_values_hash, function_value });

    process_execution_results(function_value);
}


void  typed_minimization_analysis::process_execution_results(branching_function_value_type const  function_value)
{
    switch (progress_stage)
    {
        case SEED:
            if (std::isfinite(function_value))
            {
                current_function_value = function_value;
                progress_stage = PARTIALS;
                partial_variable_values.clear();
                partial_function_values.clear();
            }
            break;
        case PARTIALS:
            partial_function_values.push_back(function_value);
            if (partial_function_values.size() == types_of_variables.size())
            {
                compute_gradient();
                compute_step_variables();
                if (step_variable_values.empty())
                    progress_stage = SEED;
                else
                {
                    progress_stage = STEP;
                    step_function_values.clear();
                    ++statistics.gradient_steps;
                }
            }
            break;
        case STEP:
            step_function_values.push_back(function_value);
            if (step_function_values.size() == step_variable_values.size())
                switch (compute_current_variable_and_function_value_from_step())
                {
                    case 0U: // Regular gradient step (we got closer to the minimum)
                        progress_stage = PARTIALS;
                        partial_variable_values.clear();
                        partial_function_values.clear();
                        break;
                    case 1U: // We locked some gradient coordinates => let's step in other directions.
                        compute_step_variables();
                        step_function_values.clear();
                        break;
                    case 2U:
                        progress_stage = SEED;
                        break;
                    default: UNREACHABLE(); break;
                }
            break;
        default: { UNREACHABLE(); }
    }
}


void  typed_minimization_analysis::generate_next_seed()
{
    natural_16_bit constexpr  min_exponent = 8U;
    static std::unordered_map<type_of_input_bits, natural_16_bit> const  types_to_exponents {
        { type_of_input_bits::UINT16, 16 - min_exponent },
        { type_of_input_bits::SINT16, 15 - min_exponent },
        { type_of_input_bits::UINT32, 32 - min_exponent },
        { type_of_input_bits::SINT32, 31 - min_exponent },
        { type_of_input_bits::UINT64, 64 - min_exponent },
        { type_of_input_bits::SINT64, 63 - min_exponent },
        { type_of_input_bits::FLOAT32, 127 - min_exponent },
        { type_of_input_bits::FLOAT64, 1023 - min_exponent },
    };

    float_64_bit const  progress = (float_64_bit)num_fast_and_genuine_executions / (float_64_bit)max_num_executions();

    current_variable_values.clear();
    for (type_of_input_bits const  type : types_of_variables)
    {
        auto const  it = types_to_exponents.find(type);
        float_64_bit const  max_abs_value = (it == types_to_exponents.end()) ? 0.0 :
            std::round(std::pow(2.0, min_exponent + (float_64_bit)it->second * progress) - 1.0);

        current_variable_values.push_back({});
        switch (type)
        {
            case type_of_input_bits::BOOLEAN:
                current_variable_values.back().value_boolean = get_random_natural_32_bit_in_range(1, 100, random_generator32) < 50;
                break;
            case type_of_input_bits::UINT8:
                current_variable_values.back().value_uint8 =(natural_8_bit)get_random_natural_32_bit_in_range(
                        std::numeric_limits<natural_8_bit>::min(),
                        std::numeric_limits<natural_8_bit>::max(),
                        random_generator32
                        );
                break;
            case type_of_input_bits::SINT8:
                current_variable_values.back().value_sint8 =(integer_8_bit)get_random_integer_32_bit_in_range(
                        std::numeric_limits<integer_8_bit>::min(),
                        std::numeric_limits<integer_8_bit>::max(),
                        random_generator32
                        );
                break;
            case type_of_input_bits::UINT16:
                current_variable_values.back().value_uint16 =(natural_16_bit)get_random_natural_32_bit_in_range(
                        std::numeric_limits<natural_16_bit>::min(),
                        (natural_16_bit)max_abs_value,
                        random_generator32
                        );
                break;
            case type_of_input_bits::SINT16:
                current_variable_values.back().value_sint16 =(integer_16_bit)get_random_integer_32_bit_in_range(
                        -(integer_16_bit)max_abs_value,
                        (integer_16_bit)max_abs_value,
                        random_generator32
                        );
                break;
            case type_of_input_bits::UINT32:
                current_variable_values.back().value_uint32 =(natural_32_bit)get_random_natural_32_bit_in_range(
                        std::numeric_limits<natural_32_bit>::min(),
                        (natural_32_bit)max_abs_value,
                        random_generator32
                        );
                break;
            case type_of_input_bits::SINT32:
                current_variable_values.back().value_sint32 =(integer_32_bit)get_random_integer_32_bit_in_range(
                        -(integer_32_bit)max_abs_value,
                        (integer_32_bit)max_abs_value,
                        random_generator32
                        );
                break;
            case type_of_input_bits::UINT64:
                current_variable_values.back().value_uint64 =(natural_64_bit)get_random_natural_64_bit_in_range(
                        std::numeric_limits<natural_64_bit>::min(),
                        (natural_64_bit)max_abs_value,
                        random_generator64
                        );
                break;
            case type_of_input_bits::SINT64:
                current_variable_values.back().value_sint64 =(integer_64_bit)get_random_integer_64_bit_in_range(
                        -(integer_64_bit)max_abs_value,
                        (integer_64_bit)max_abs_value,
                        random_generator64
                        );
                break;
            case type_of_input_bits::FLOAT32:
                current_variable_values.back().value_float32 = get_random_float_32_bit_in_range(
                        -(float_32_bit)max_abs_value,
                        (float_32_bit)max_abs_value,
                        random_generator32
                        );
                break;
            case type_of_input_bits::FLOAT64:
                current_variable_values.back().value_float64 = get_random_float_64_bit_in_range(
                        -max_abs_value,
                        max_abs_value,
                        random_generator64
                        );
                break;
            default: { UNREACHABLE(); }
        }
    }
}


template<typename float_type>
static float_type  find_best_floating_point_variable_delta(float_type const v0, branching_function_value_type const f0)
{
    float_type constexpr  under_linear_estimate{ 0.1 };
    float_type constexpr  half{ 0.5 };
    float_type  mult{ half };
    while (v0 + (half * mult) * v0 != v0 && std::fabs((half * mult) * v0) >= std::fabs(under_linear_estimate * f0))
        mult *= half;
    return mult * std::fabs(v0);
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
            partial_variable_values.back().value_float32 +=
                    find_best_floating_point_variable_delta(partial_variable_values.back().value_float32, current_function_value);
            break;
        case type_of_input_bits::FLOAT64:
            partial_variable_values.back().value_float64 +=
                    find_best_floating_point_variable_delta(partial_variable_values.back().value_float64, current_function_value);
            break;
        default: { UNREACHABLE(); }
    }
}


void  typed_minimization_analysis::compute_gradient()
{
    INVARIANT(partial_variable_values.size() == types_of_variables.size());

    gradient.clear();
    gradient_direction_locks.clear();

    branching_function_value_type const  f0 = std::fabs(current_function_value);

    for (std::size_t  i = 0U; i != partial_function_values.size(); ++i)
    {
        if (!std::isfinite(partial_function_values.at(i)))
        {
            gradient.push_back(0.0);
            gradient_direction_locks.push_back(true);
            continue;
        }

        branching_function_value_type const  f1 = std::fabs(partial_function_values.at(i));
        branching_function_value_type const  df = f1 - f0;

        value_of_variable const&  var0 = current_variable_values.at(i);
        value_of_variable const&  var1 = partial_variable_values.at(i);

        branching_function_value_type  dv;
        switch (types_of_variables.at(i))
        {
            case type_of_input_bits::BOOLEAN:
                dv = 1.0;
                break;
            case type_of_input_bits::UINT8:
                dv = (branching_function_value_type)(var1.value_uint8 - var0.value_uint8);
                break;
            case type_of_input_bits::SINT8:
                dv = (branching_function_value_type)(var1.value_sint8 - var0.value_sint8);
                break;
            case type_of_input_bits::UINT16:
                dv = (branching_function_value_type)(var1.value_uint16 - var0.value_uint16);
                break;
            case type_of_input_bits::SINT16:
                dv = (branching_function_value_type)(var1.value_sint16 - var0.value_sint16);
                break;
            case type_of_input_bits::UINT32:
                dv = (branching_function_value_type)(var1.value_uint32 - var0.value_uint32);
                break;
            case type_of_input_bits::SINT32:
                dv = (branching_function_value_type)(var1.value_sint32 - var0.value_sint32);
                break;
            case type_of_input_bits::UINT64:
                dv = (branching_function_value_type)(var1.value_uint64 - var0.value_uint64);
                break;
            case type_of_input_bits::SINT64:
                dv = (branching_function_value_type)(var1.value_sint64 - var0.value_sint64);
                break;
            case type_of_input_bits::FLOAT32:
                dv = (branching_function_value_type)(var1.value_float32 - var0.value_float32);
                break;
            case type_of_input_bits::FLOAT64:
                dv = (branching_function_value_type)(var1.value_float64 - var0.value_float64);
                break;
            default: { UNREACHABLE(); }
        }

        INVARIANT(dv != 0.0);

        branching_function_value_type const  gradient_value = df / dv;
        if (std::isfinite(gradient_value))
        {
            gradient.push_back(gradient_value);
            gradient_direction_locks.push_back(false);
        }
        else
        {
            gradient.push_back(0.0);
            gradient_direction_locks.push_back(true);
        }
    }
}


void  typed_minimization_analysis::compute_step_variables()
{
    INVARIANT(gradient.size() == types_of_variables.size());

    step_variable_values.clear();

    branching_function_value_type  grad_length_squared = 0.0;   // I.e., dot(gradient,gradient)
    for (std::size_t  i = 0U; i != gradient.size(); ++i)
        if (!gradient_direction_locks.at(i))
        {
            branching_function_value_type const  partial = gradient.at(i);
            grad_length_squared += partial * partial;
        }
    if (grad_length_squared == 0.0 || !std::isfinite(grad_length_squared))
        return;

    branching_function_value_type  max_lambda = std::fabs(current_function_value) / grad_length_squared;
    if (max_lambda == 0.0 || !std::isfinite(max_lambda))
        return;

    static std::vector<float_64_bit> const multipliers {
        1000.0,
        100.0,
        10.0,
        1.0,
        0.1,
        0.01,
        0.001,
        };

    for (float_64_bit const  m : multipliers)
    {
        float_64_bit const  t = m * max_lambda;
        step_variable_values.push_back({});
        auto&  vars = step_variable_values.back();
        for (std::size_t  i = 0U; i != types_of_variables.size(); ++i)
        {
            step_variable_values.back().push_back({});
            value_of_variable&  var = step_variable_values.back().back();
            value_of_variable const&  var0 = current_variable_values.at(i);
            if (gradient_direction_locks.at(i))
            {
                var = var0;
                continue;
            }
            branching_function_value_type const  partial = gradient.at(i);
            switch (types_of_variables.at(i))
            {
                case type_of_input_bits::UINT8:
                    var.value_uint8 = (natural_8_bit)std::round(var0.value_uint8 - t * partial);
                    break;
                case type_of_input_bits::SINT8:
                    var.value_sint8 = (integer_8_bit)std::round(var0.value_sint8 - t * partial);
                    break;
                case type_of_input_bits::UINT16:
                    var.value_uint16 = (natural_16_bit)std::round(var0.value_uint16 - t * partial);
                    break;
                case type_of_input_bits::SINT16:
                    var.value_sint16 = (integer_16_bit)std::round(var0.value_sint16 - t * partial);
                    break;
                case type_of_input_bits::UINT32:
                    var.value_uint32 = (natural_32_bit)std::round(var0.value_uint32 - t * partial);
                    break;
                case type_of_input_bits::SINT32:
                    var.value_sint32 = (integer_32_bit)std::round(var0.value_sint32 - t * partial);
                    break;
                case type_of_input_bits::UINT64:
                    var.value_uint64 = var0.value_uint64 - (natural_64_bit)std::round(t * partial);
                    break;
                case type_of_input_bits::SINT64:
                    var.value_sint64 = var0.value_sint64 - (integer_64_bit)std::round(t * partial);
                    break;
                case type_of_input_bits::FLOAT32:
                    var.value_float32 = (float_32_bit)(var0.value_float32 - t * partial);
                    break;
                case type_of_input_bits::FLOAT64:
                    var.value_float64 = var0.value_float64 - t * partial;
                    break;
                default: { UNREACHABLE(); }
            }
        }
    }
}


natural_8_bit  typed_minimization_analysis::compute_current_variable_and_function_value_from_step()
{
    INVARIANT(step_function_values.size() == step_variable_values.size());
    INVARIANT(std::isfinite(current_function_value));

    bool variables_updated = false;
    for (std::size_t  i = 0U; i != step_function_values.size(); ++i)
    {
        branching_function_value_type const  value = step_function_values.at(i);
        if (std::isfinite(value) && std::fabs(value) < std::fabs(current_function_value))
        {
            current_variable_values = step_variable_values.at(i);
            current_function_value = value;
            variables_updated = true;
        }
    }
    if (variables_updated)
        return 0;

    branching_function_value_type  min_lambda = std::numeric_limits<branching_function_value_type>::max();
    branching_function_value_type  max_lambda = 0.0;

    bool  some_variable_locked = false;

    std::vector<branching_function_value_type>  lambda_per_partial;
    for (std::size_t  i = 0U; i != gradient_direction_locks.size(); ++i)
        if (gradient_direction_locks.at(i))
            lambda_per_partial.push_back(INFINITY);
        else
        {
            branching_function_value_type const  partial = gradient.at(i);
            branching_function_value_type const  partial_squared = partial * partial;
            if (partial_squared == 0.0)
            {
                lambda_per_partial.push_back(INFINITY);
                gradient_direction_locks.at(i) = true;
                some_variable_locked = true;
                continue;
            }
            branching_function_value_type const  lambda = std::fabs(1.0 / partial_squared);
            if (lambda == 0.0 || !std::isfinite(lambda))
            {
                lambda_per_partial.push_back(INFINITY);
                gradient_direction_locks.at(i) = true;
                some_variable_locked = true;
                continue;
            }
            lambda_per_partial.push_back(lambda);
            min_lambda = std::min(min_lambda, lambda);
            max_lambda = std::max(max_lambda, lambda);
        }

    branching_function_value_type  lambda_limit = 0.5 * min_lambda + 0.5 * max_lambda + 0.1 * (max_lambda - min_lambda);

    natural_32_bit  num_unlocked_vars = 0U;
    for (std::size_t  i = 0U; i != gradient_direction_locks.size(); ++i)
        if (!gradient_direction_locks.at(i))
        {
            branching_function_value_type const  lambda = lambda_per_partial.at(i);
            if (!std::isfinite(lambda) || lambda < lambda_limit)
            {
                gradient_direction_locks.at(i) = true;
                some_variable_locked = true;
            }
            else
                ++num_unlocked_vars;
        }

    return some_variable_locked && num_unlocked_vars > 0U ? 1U : 2U;
}


bool  typed_minimization_analysis::apply_fast_execution_using_cache()
{
    vecb  bits;
    collect_bits_of_executed_variable_values([&bits](natural_32_bit, bool const  state) { bits.push_back(state); });

    executed_variable_values_hash = make_hash(bits);

    auto const  hash_it = hashes_of_generated_bits.find(executed_variable_values_hash);
    if (hash_it == hashes_of_generated_bits.end())
        return false;

    process_execution_results(hash_it->second);

    ++statistics.suppressed_repetitions;

    // recorder().on_minimization_execution_results_cache_hit(descent.stage, hash_it->first);

    return true;
}

void  typed_minimization_analysis::collect_bits_of_executed_variable_values(std::function<void(natural_32_bit, bool)> const&  bits_collector) const
{
    for (std::size_t  i = 0UL; i != from_variables_to_input.size(); ++i)
    {
        vecb  bits;
        natural_8_bit const* const  value_ptr = &executed_variable_values.at(i).value_uint8;
        bytes_to_bits(value_ptr, value_ptr + num_bytes(types_of_variables.at(i)), bits);

        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            bits_collector(mapping.input_start_bit_index + idx, bits.at(idx));
    }
}


}
