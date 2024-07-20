#include <fuzzing/chain_minimization_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <map>
#include <algorithm>

namespace  fuzzing {


bool  chain_minimization_analysis::are_types_of_sensitive_bits_available(
        stdin_bits_and_types_pointer  bits_and_types,
        std::unordered_set<stdin_bit_index> const&  sensitive_bits
        )
{
    for (stdin_bit_index  idx : sensitive_bits)
        if (!is_known_type(bits_and_types->type_of_bit(idx)))
            return false;
    return !sensitive_bits.empty();
}


chain_minimization_analysis::chain_minimization_analysis()
    : state{ READY }
    , node{ nullptr }
    , bits_and_types{ nullptr }
    , execution_id{ 0 }
    , path{}
    , from_variables_to_input{}
    , types_of_variables{}
    , stopped_early{ false }
    , failed_nodes{}
    , num_executions{ 0U }
    , progress_stage{ PARTIALS }
    , origin{}
    , origin_in_reals{}
    , local_spaces{}
    , gradient_step_shifts{}
    , gradient_step_results{}
    , recovery{}
    , statistics{}
{}


bool  chain_minimization_analysis::is_disabled() const
{
    return false;
}


void  chain_minimization_analysis::start(
        branching_node* const  node_ptr,
        stdin_bits_and_types_pointer const  bits_and_types_ptr,
        natural_32_bit const  execution_id_
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && bits_and_types_ptr != nullptr);
    ASSUMPTION(node_ptr->is_direction_unexplored(false) || node_ptr->is_direction_unexplored(true));

    state = BUSY;
    node = node_ptr;
    bits_and_types = bits_and_types_ptr;
    execution_id = execution_id_;

    path.clear();
    path.push_back({
            node,
            node->best_trace->at(node->trace_index).value,
            node->is_direction_unexplored(false) ? false : true,
            node->is_direction_unexplored(false) ? opposite_predicate(node->branching_predicate) : node->branching_predicate,
            {}
            });
    for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
        path.push_back({
                n,
                node->best_trace->at(n->trace_index).value,
                n->successor_direction(s),
                n->successor_direction(s) ? n->branching_predicate : opposite_predicate(n->branching_predicate),
                {}
                });
    std::reverse(path.begin(), path.end());

    std::map<natural_32_bit, std::pair<type_of_input_bits, std::unordered_set<natural_8_bit> > >  start_bits_to_bit_indices;
    for (natural_32_bit  i = 0U, i_end = (natural_32_bit)path.size(); i != i_end; ++i)
        for (stdin_bit_index  idx : path.at(i).node_ptr->sensitive_stdin_bits)
        {
            natural_32_bit const  type_index = bits_and_types->type_index(idx);
            natural_32_bit const  start_bit_idx = bits_and_types->type_start_bit_index(type_index);
            auto const  it_and_state = start_bits_to_bit_indices.insert({ start_bit_idx, { bits_and_types->types.at(type_index), {} } });
            it_and_state.first->second.second.insert(idx - start_bit_idx);
        }

    std::unordered_map<natural_32_bit, natural_32_bit>  start_bits_to_variable_indices;
    types_of_variables.clear();
    from_variables_to_input.clear();
    for (auto&  start_and_type_and_indices : start_bits_to_bit_indices)
    {
        start_bits_to_variable_indices.insert({ start_and_type_and_indices.first, (natural_32_bit)from_variables_to_input.size() });
        types_of_variables.push_back(start_and_type_and_indices.second.first);
        from_variables_to_input.push_back({ start_and_type_and_indices.first, {} });
        from_variables_to_input.back().value_bit_indices.assign(
                start_and_type_and_indices.second.second.begin(),
                start_and_type_and_indices.second.second.end()
                );
        std::sort(from_variables_to_input.back().value_bit_indices.begin(), from_variables_to_input.back().value_bit_indices.end());
    }

    INVARIANT(!types_of_variables.empty());

    for (natural_32_bit  i = 0U, i_end = (natural_32_bit)path.size(); i != i_end; ++i)
    {
        branching_info&  info = path.at(i);
        for (stdin_bit_index  idx : info.node_ptr->sensitive_stdin_bits)
        {
            natural_32_bit const  type_index = bits_and_types->type_index(idx);
            natural_32_bit const  start_bit_idx = bits_and_types->type_start_bit_index(type_index);
            info.variable_indices.insert(start_bits_to_variable_indices.at(start_bit_idx));
        }
    }

    stopped_early = false;
    num_executions = 0U;

    progress_stage = PARTIALS;

    load_origin(bits_and_types->bits);

    local_spaces.clear();
    insert_first_local_space();

    gradient_step_shifts.clear();
    gradient_step_results.clear();

    recovery = {};

    ++statistics.start_calls;

    // recorder().on_typed_minimization_start(node, from_variables_to_input, types_of_variables, bits_and_types);
}


void  chain_minimization_analysis::stop()
{
    if (!is_busy())
        return;

    if (num_executions < max_num_executions())
    {
        stopped_early = true;

        // recorder().on_typed_minimization_stop(progress_recorder::EARLY);

        ++statistics.stop_calls_early;
    }
    else
    {
        // recorder().on_typed_minimization_stop(progress_recorder::REGULAR);

        ++statistics.stop_calls_regular;
    }

    node->minimization_performed = true;
    node->minimization_start_execution = execution_id;

    state = READY;
}


void  chain_minimization_analysis::stop_with_failure()
{
    if (!is_busy())
        return;

    stopped_early = true;
    // failed_nodes.insert(node);

    node->minimization_performed = true;
    node->minimization_start_execution = execution_id;

    state = READY;

    ++statistics.stop_calls_failed;
}


natural_32_bit  chain_minimization_analysis::max_num_executions() const
{
    return (natural_32_bit)(100U * node->num_stdin_bytes);
}


bool  chain_minimization_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (num_executions >= max_num_executions())
    {
        stop_with_failure();
        return false;
    }

    while (true)
    {
        if (progress_stage == PARTIALS)
        {
            if (compute_shift_of_next_partial())
            {
                transform_shift(local_spaces.size() - 1UL);
                break;
            }

            if (!compute_gradient_step_shifts())
            {
                stop_with_failure();
                return false;
            }

            progress_stage = STEP;
            gradient_step_results.clear();
        }
        else if (progress_stage == STEP)
        {
            if (gradient_step_results.size() < gradient_step_shifts.size())
            {
                local_spaces.back().sample_shift = gradient_step_shifts.at(gradient_step_results.size());
                transform_shift(local_spaces.size() - 1UL);
                break;
            }
            if (apply_best_gradient_step())
                progress_stage = PARTIALS;
            else
            {
                stop_with_failure();
                return false;
            }
        }
        else // progress_stage == RECOVERY
        {
            if (!recovery.sample_shifts.empty())
            {
                local_spaces.at(recovery.space_index).sample_shift = recovery.sample_shifts.back();
                recovery.sample_shifts.pop_back();
                transform_shift(recovery.space_index);
                break;
            }

            stop_with_failure();
            return false;
        }
    }

    store_shifted_origin(bits_ref);

    ++statistics.generated_inputs;

    return true;
}


void  chain_minimization_analysis::process_execution_results(
        execution_trace_pointer const  trace_ptr,
        stdin_bits_and_types_pointer const  bits_and_types_ptr
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr);

    ++num_executions;

    if (trace_ptr->empty())
    {
        // We diverged even before the first branching in the program (perhaps due to some crash, like division by zero).
        stop_with_failure();
        return;
    }

    std::size_t  last_index{ 0UL };
    for (std::size_t const  n = std::min({ local_spaces.size(), trace_ptr->size() }); last_index != n; ++last_index)
    {
        if (trace_ptr->at(last_index).id != path.at(last_index).node_ptr->id)
            break;
        local_spaces.at(last_index).sample_value = trace_ptr->at(last_index).value;
        if (last_index < local_spaces.size() - 1UL && trace_ptr->at(last_index).direction != path.at(last_index).direction)
            break;
    }

    if (last_index != local_spaces.size())
    {
        if (progress_stage != RECOVERY)
        {
            recovery = {};
            recovery.stage_backup = progress_stage;
            recovery.shift_backup = local_spaces.at(last_index).sample_shift;
            recovery.value_backup = local_spaces.at(last_index).sample_value;
            recovery.space_index = last_index;
            recovery.shift_best = recovery.shift_backup;
            recovery.value_best = recovery.value_backup;
            __compute_gradient_step_shifts(
                    recovery.sample_shifts,
                    local_spaces.at(recovery.space_index),
                    recovery.value_best,
                    path.at(recovery.space_index).predicate,
                    &recovery.shift_best
                    );
            std::reverse(recovery.sample_shifts.begin(), recovery.sample_shifts.end());

            progress_stage = RECOVERY;
        }
        else
        {
            if (recovery.space_index == last_index)
            {
                if (std::fabs(local_spaces.at(recovery.space_index).sample_value) <= std::fabs(recovery.value_best))
                {
                    recovery.shift_best = local_spaces.at(last_index).sample_shift;
                    recovery.value_best = local_spaces.at(last_index).sample_value;
                    std::size_t const  old_size{ recovery.sample_shifts.size() };
                    __compute_gradient_step_shifts(
                            recovery.sample_shifts,
                            local_spaces.at(recovery.space_index),
                            recovery.value_best,
                            path.at(recovery.space_index).predicate,
                            &recovery.shift_best
                            );
                    std::reverse(std::next(recovery.sample_shifts.begin(), old_size), recovery.sample_shifts.end());
                }
            }
            else if (recovery.space_index < last_index)
            {
                recovery.shift_backup = local_spaces.at(last_index).sample_shift;
                recovery.value_backup = local_spaces.at(last_index).sample_value;
                recovery.space_index = last_index;
                recovery.shift_best = recovery.shift_backup;
                recovery.value_best = recovery.value_backup;
                recovery.sample_shifts.clear();
                __compute_gradient_step_shifts(
                        recovery.sample_shifts,
                        local_spaces.at(recovery.space_index),
                        recovery.value_best,
                        path.at(recovery.space_index).predicate,
                        &recovery.shift_best
                        );
                std::reverse(recovery.sample_shifts.begin(), recovery.sample_shifts.end());
            }
        }
    }
    else if (progress_stage == RECOVERY)
        progress_stage = recovery.stage_backup;

    switch (progress_stage)
    {
        case PARTIALS:
            compute_partial_derivative();
            if (size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis))
            {
                if (local_spaces.size() < path.size())
                    insert_next_local_space();
                else
                {
                    progress_stage = STEP;
                    compute_gradient_step_shifts();
                }
            }
            ++statistics.partials;
            break;
        case STEP:
            if (gradient_step_results.size() < gradient_step_shifts.size())
            {
                gradient_step_results.push_back({ bits_and_types_ptr, {} });
                for (auto const&  space : local_spaces)
                    gradient_step_results.back().values.push_back(space.sample_value);
            }
            ++statistics.gradient_steps;
            break;
        case RECOVERY:
            break;
        default: { UNREACHABLE(); } break;
    }

    // recorder().on_typed_minimization_execution_results_available(
    //         progress_stage,
    //         executed_variable_values,
    //         function_value,
    //         executed_variable_values_hash
    //         );
}


bool  chain_minimization_analysis::compute_shift_of_next_partial()
{
    while (size(local_spaces.back().gradient) < columns(local_spaces.back().orthogonal_basis))
    {
        std::size_t const  space_index{ local_spaces.size() - 1UL };

        local_space_of_branching&  space{ local_spaces.at(space_index) };

        while (size(space.gradient) < columns(space.orthogonal_basis))
        {
            std::size_t const  partial_index{ size(space.gradient) };
    
            bool  has_sensitive_var{ false };
            natural_32_bit  smallest_var_idx;
            {
                auto const&  sensitive_vars{ path.at(space_index).variable_indices };
                auto const&  vars{ space.variable_indices.at(partial_index) };
                smallest_var_idx = vars.front();
                for (natural_32_bit  var_idx : vars)
                {
                    if (sensitive_vars.contains(var_idx))
                        has_sensitive_var = true;
                    if (to_id(types_of_variables.at(var_idx)) < to_id(types_of_variables.at(smallest_var_idx)))
                        smallest_var_idx = var_idx;
                }
            }

            if (has_sensitive_var)
            {
                set(space.sample_shift, 0.0);
                float_64_bit&  shift{ at(space.sample_shift, partial_index) };

                auto const  float_shift_pivot = [this](natural_32_bit const  i) {
                    float_64_bit const  x{ std::fabs(origin_in_reals.at(i)) };
                    float_64_bit const  fx{ std::fabs(path.at(local_spaces.size() - 1UL).value) };
                    return x + 0.1 * (fx - x);
                };

                switch (types_of_variables.at(smallest_var_idx))
                {
                    case type_of_input_bits::FLOAT32:
                        shift = small_delta_around((float_32_bit)float_shift_pivot(smallest_var_idx));
                        break;
                    case type_of_input_bits::FLOAT64:
                        shift = small_delta_around(float_shift_pivot(smallest_var_idx));
                        break;
                    default:
                        shift = 1.0;
                        break;
                }

                if (are_constraints_satisfied(space.constraints, space.sample_shift))
                    return true;

                shift = -shift;
                if (!are_constraints_satisfied(space.constraints, space.sample_shift))
                    return true;
            }

            space.gradient.push_back(0.0);
        }

        if (local_spaces.size() < path.size())
            insert_next_local_space();
    }

    return false;
}


void  chain_minimization_analysis::compute_partial_derivative()
{
    local_space_of_branching&  space{ local_spaces.back() };
    ASSUMPTION(size(space.gradient) < columns(space.orthogonal_basis));
    float_64_bit const partial{ (space.sample_value - path.at(local_spaces.size() - 1UL).value) / at(space.sample_shift, size(space.gradient)) };
    space.gradient.push_back(std::isfinite(partial) ? partial : 0.0);
}


void  chain_minimization_analysis::transform_shift(std::size_t const  src_space_index)
{
    for (std::size_t  i = src_space_index; i > 0UL; --i)
    {
        vecf64&  shift{ local_spaces.at(i - 1UL).sample_shift };
        set(shift, 0.0);
        local_space_of_branching const&  space{ local_spaces.at(i) };
        for (std::size_t  j = 0UL; j < columns(space.orthogonal_basis); ++j)
            add_scaled(shift, at(space.sample_shift, j), column(space.orthogonal_basis, j));
    }
}


void  chain_minimization_analysis::insert_first_local_space()
{
    ASSUMPTION(local_spaces.empty());

    local_spaces.push_back({});
    for (natural_32_bit  i = 0U, i_end = (natural_32_bit)types_of_variables.size(); i != i_end; ++i)
    {
        local_spaces.back().orthogonal_basis.push_back({});
        axis(local_spaces.back().orthogonal_basis.back(), types_of_variables.size(), i);
        local_spaces.back().variable_indices.push_back({ i });
    }
    reset(local_spaces.back().sample_shift, columns(local_spaces.back().orthogonal_basis), 0.0);
}


void  chain_minimization_analysis::insert_next_local_space()
{
    ASSUMPTION(local_spaces.size() < path.size() && size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis));

    local_spaces.push_back({});

    local_space_of_branching const&  src_space{ local_spaces.at(local_spaces.size() - 2UL) };
    local_space_of_branching&  dst_space{ local_spaces.at(local_spaces.size() - 1UL) };

    float_64_bit const  gg{ dot_product(src_space.gradient, src_space.gradient) };
    float_64_bit const  gg_inv{ 1.0 / gg };
    if (!std::isfinite(gg) || std::isnan(gg) || !std::isfinite(gg_inv) || std::isnan(gg_inv))
    {
        for (natural_32_bit  i = 0U; i != columns(src_space.orthogonal_basis); ++i)
        {
            dst_space.orthogonal_basis.push_back({});
            axis(dst_space.orthogonal_basis.back(), columns(src_space.orthogonal_basis), i);
            dst_space.variable_indices.push_back(src_space.variable_indices.at(i));
        }
        dst_space.constraints = src_space.constraints;
        reset(dst_space.sample_shift, columns(dst_space.orthogonal_basis), 0.0);
        return;
    }
    float_64_bit const  g_len{ std::sqrt(gg) };

    auto const& collect_variable_indices_for_last_basis_vector = [&src_space, &dst_space]() {
        std::unordered_set<natural_32_bit>  indices;
        for (std::size_t  i = 0UL; i != columns(src_space.orthogonal_basis); ++i)
            if (std::fabs(at(dst_space.orthogonal_basis.back(), i)) > 1e-6f)
                indices.insert(src_space.variable_indices.at(i).begin(), src_space.variable_indices.at(i).end());

        while (dst_space.variable_indices.size() < dst_space.orthogonal_basis.size())
            dst_space.variable_indices.push_back({});

        dst_space.variable_indices.back().assign(indices.begin(), indices.end());
        std::sort(dst_space.variable_indices.back().begin(), dst_space.variable_indices.back().end());
    };

    for (std::size_t  i = 0UL; i < columns(src_space.orthogonal_basis); ++i)
    {
        vecf64  w;
        axis(w, columns(src_space.orthogonal_basis), i);

        float_64_bit wg{ dot_product(w, src_space.gradient) };
        if (std::fabs(wg) < 1e-6)
        {
            dst_space.orthogonal_basis.push_back(w);
            collect_variable_indices_for_last_basis_vector();
        }
        else
        {
            add_scaled(w, -wg * gg_inv, src_space.gradient);
            for (vecf64 const&  v : dst_space.orthogonal_basis)
                add_scaled(w, -dot_product(w, v) / dot_product(v, v), v);
            float_64_bit const  ww{ dot_product(w, w) };
            if (ww > 1e-6)
            {
                float_64_bit const  w_len{ std::sqrt(ww) };
                scale(w, g_len / w_len);
                dst_space.orthogonal_basis.push_back(w);
                collect_variable_indices_for_last_basis_vector();
            }
        }
    }

    branching_info const&  src_info{ path.at(local_spaces.size() - 2UL) };
    if (src_info.predicate != BP_EQUAL)
    {
        dst_space.orthogonal_basis.push_back(src_space.gradient);
        collect_variable_indices_for_last_basis_vector();
        vecf64  normal;
        axis(normal, columns(src_space.orthogonal_basis), columns(src_space.orthogonal_basis) - 1UL);
        dst_space.constraints.push_back({
            normal,
            -src_info.value * gg_inv,
            src_info.predicate
        });
    }

    for (spatial_constraint const&  constraint : src_space.constraints)
    {
        vecf64  normal;
        for (vecf64 const&  u : dst_space.orthogonal_basis)
            normal.push_back(dot_product(constraint.normal, u) / length(u));
        float_64_bit const  denom{ dot_product(constraint.normal, mul(dst_space.orthogonal_basis, normal)) };
        if (std::fabs(denom) > 1e-6f)
            dst_space.constraints.push_back({
                normal,
                constraint.param * (dot_product(constraint.normal, constraint.normal) / denom),
                constraint.predicate
            });
    }

    reset(dst_space.sample_shift, columns(dst_space.orthogonal_basis), 0.0);
}


bool  chain_minimization_analysis::are_constraints_satisfied(std::vector<spatial_constraint> const& constraints, vecf64 const&  shift) const
{
    for (spatial_constraint const&  constraint : constraints)
    {
        float_64_bit const  param{ dot_product(shift, constraint.normal) / dot_product(constraint.normal, constraint.normal) };
        switch (constraint.predicate)
        {
            case BP_UNEQUAL:
                if (std::fabs(param - constraint.param) < 1e-6f)
                    return false;
                break;
            case BP_LESS:
                if (param >= constraint.param)
                    return false;
                break;
            case BP_LESS_EQUAL:
                if (param > constraint.param)
                    return false;
                break;
            case BP_GREATER:
                if (param <= constraint.param)
                    return false;
                break;
            case BP_GREATER_EQUAL:
                if (param < constraint.param)
                    return false;
                break;
            default: { UNREACHABLE(); } break;
        }
    }
    return true;
}


bool  chain_minimization_analysis::clip_shift_by_constraints(
        std::vector<spatial_constraint> const& constraints,
        vecf64 const&  gradient,
        vecf64&  shift,
        std::size_t const  max_iterations
        ) const
{
    for (std::size_t  iteration = 0UL; iteration != max_iterations; ++iteration)
    {
        bool  clipped{ false };
        for (spatial_constraint const&  constraint : constraints)
        {
            vecf64  direction{ component_of_first_orthogonal_to_second(constraint.normal, gradient) };
            if (dot_product(direction, direction) < 0.01 * dot_product(constraint.normal, constraint.normal))
                direction = constraint.normal;

            float_64_bit const  param{ dot_product(shift, constraint.normal) / dot_product(constraint.normal, constraint.normal) };
            float_64_bit const  delta{ constraint.param - param };
            float_64_bit const  scale{ dot_product(constraint.normal, constraint.normal) / dot_product(direction, constraint.normal) };
            float_64_bit const  scale_delta{ scale * delta };
            float_64_bit const  direction_length{ length(direction) };
            float_64_bit const  step{ std::fabs(small_delta_around(scale_delta * direction_length)) / direction_length };
            float_64_bit const  scale_delta_step{ scale_delta < 0.0 ? scale_delta - step : scale_delta + step };
            switch (constraint.predicate)
            {
                case BP_UNEQUAL:
                    if (delta == 0.0)
                    {
                        add_scaled(shift, (iteration % 2) == 0 ? 0.1 : -0.1, direction);
                        clipped = true;
                    }
                    break;
                case BP_LESS:
                    if (delta == 0.0)
                    {
                        add_scaled(shift, -step, direction);
                        clipped = true;
                    }
                    else if (delta < 0.0)
                    {
                        add_scaled(shift, scale_delta_step, direction);
                        clipped = true;
                    }
                    break;
                case BP_LESS_EQUAL:
                    if (delta < 0.0)
                    {
                        add_scaled(shift, scale_delta_step, direction);
                        clipped = true;
                    }
                    break;
                case BP_GREATER:
                    if (delta == 0.0)
                    {
                        add_scaled(shift, step, direction);
                        clipped = true;
                    }
                    else if (delta > 0.0)
                    {
                        add_scaled(shift, scale_delta_step, direction);
                        clipped = true;
                    }
                    break;
                case BP_GREATER_EQUAL:
                    if (delta > 0.0)
                    {
                        add_scaled(shift, scale_delta_step, direction);
                        clipped = true;
                    }
                    break;
                default: { UNREACHABLE(); } break;
            }
        }
        if (!clipped)
            return true;
    }
    return false;
}


bool  chain_minimization_analysis::compute_gradient_step_shifts()
{
    ASSUMPTION(local_spaces.size() == path.size() && size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis));

    gradient_step_shifts.clear();
    gradient_step_results.clear();

    // __compute_gradient_step_shifts(
    //         gradient_step_shifts,
    //         local_spaces.back(),
    //         path.back().value,
    //         path.back().predicate,
    //         nullptr
    //         );

    local_space_of_branching const&  space{ local_spaces.back() };
    float_64_bit const  gg_inv{ 1.0 / dot_product(space.gradient, space.gradient) };
    if (!std::isfinite(gg_inv) || std::isnan(gg_inv))
        return false;

    float_64_bit const  lambda0{ -path.back().value * gg_inv };
    if (!std::isfinite(lambda0)
            || std::isnan(lambda0)
            || ![&space, lambda0]() -> bool {
                    for (auto const coord : space.gradient)
                    {
                        float_64_bit const  x{ coord * lambda0 };
                        if (!std::isfinite(x) || std::isnan(x))
                            return false;
                    }
                    return true;
                }()
            )
        return false;

    float_64_bit const  delta{ std::fabs(small_delta_around(lambda0)) };

    std::vector<float_64_bit>  lambdas;
    {
        std::vector<float_64_bit>  raw_lambdas;
        switch (path.back().predicate)
        {
            case BP_EQUAL:
                ASSUMPTION(path.back().value != 0.0 && lambda0 != 0.0);
                raw_lambdas.assign({ lambda0 });
                break;
            case BP_UNEQUAL:
                ASSUMPTION(path.back().value == 0.0);
                raw_lambdas.assign({ lambda0 - delta, lambda0 + delta });
                break;
            case BP_LESS:
                ASSUMPTION(path.back().value >= 0.0 && lambda0 <= 0.0);
                raw_lambdas.assign({ lambda0 - delta });
                break;
            case BP_LESS_EQUAL:
                ASSUMPTION(path.back().value > 0.0 && lambda0 < 0.0);
                raw_lambdas.assign({ lambda0 - delta, lambda0 });
                break;
            case BP_GREATER:
                ASSUMPTION(path.back().value <= 0.0 && lambda0 >= 0.0);
                raw_lambdas.assign({ lambda0 + delta });
                break;
            case BP_GREATER_EQUAL:
                ASSUMPTION(path.back().value < 0.0 && lambda0 > 0.0);
                raw_lambdas.assign({ lambda0, lambda0 + delta });
                break;
            default: { UNREACHABLE(); } break;
        }

        for (auto const  lambda : raw_lambdas)
            if (std::isfinite(lambda) && !std::isnan(lambda))
                lambdas.push_back(lambda);
        if (lambdas.empty())
            lambdas.push_back(0.5 * lambda0); // This is for numerical stability - when the numbers are big - to make them smaller.

        std::sort(lambdas.begin(), lambdas.end(), [](float_64_bit x, float_64_bit y) { return std::fabs(x) < std::fabs(y); });
    }

    for (float_64_bit const  lambda : lambdas)
    {
        vecf64  shift{ scale_cp(space.gradient, lambda) };
        if (clip_shift_by_constraints(space.constraints, space.gradient, shift))
            gradient_step_shifts.push_back(shift);
    }

    return !gradient_step_shifts.empty();
}


bool  chain_minimization_analysis::__compute_gradient_step_shifts(
        std::vector<vecf64>&  resulting_shifts,
        local_space_of_branching const&  space,
        float_64_bit const  value,
        BRANCHING_PREDICATE const  predicate,
        vecf64 const* const  shift_ptr
        )
{
    float_64_bit const  gg_inv{ 1.0 / dot_product(space.gradient, space.gradient) };
    if (!std::isfinite(gg_inv) || std::isnan(gg_inv))
        return false;

    float_64_bit const  lambda0{ -value * gg_inv };
    if (!std::isfinite(lambda0)
            || std::isnan(lambda0)
            || ![&space, lambda0]() -> bool {
                    for (auto const coord : space.gradient)
                    {
                        float_64_bit const  x{ coord * lambda0 };
                        if (!std::isfinite(x) || std::isnan(x))
                            return false;
                    }
                    return true;
                }()
            )
        return false;
    float_64_bit const  delta{ std::fabs(small_delta_around(lambda0)) };

    std::vector<float_64_bit>  lambdas;
    {
        std::vector<float_64_bit>  raw_lambdas;
        switch (predicate)
        {
            case BP_EQUAL:
                ASSUMPTION(value != 0.0 && lambda0 != 0.0);
                raw_lambdas.assign({ lambda0 });
                break;
            case BP_UNEQUAL:
                ASSUMPTION(value == 0.0);
                raw_lambdas.assign({ lambda0 - delta, lambda0 + delta });
                break;
            case BP_LESS:
                ASSUMPTION(value >= 0.0 && lambda0 <= 0.0);
                raw_lambdas.assign({ lambda0 - delta });
                break;
            case BP_LESS_EQUAL:
                ASSUMPTION(value > 0.0 && lambda0 < 0.0);
                raw_lambdas.assign({ lambda0 - delta, lambda0 });
                break;
            case BP_GREATER:
                ASSUMPTION(value <= 0.0 && lambda0 >= 0.0);
                raw_lambdas.assign({ lambda0 + delta });
                break;
            case BP_GREATER_EQUAL:
                ASSUMPTION(value < 0.0 && lambda0 > 0.0);
                raw_lambdas.assign({ lambda0, lambda0 + delta });
                break;
            default: { UNREACHABLE(); } break;
        }

        for (auto const  lambda : raw_lambdas)
            if (std::isfinite(lambda) && !std::isnan(lambda))
                lambdas.push_back(lambda);
        if (lambdas.empty())
            lambdas.push_back(0.5 * lambda0); // This is for numerical stability - when the numbers are big - to make them smaller.

        std::sort(lambdas.begin(), lambdas.end(), [](float_64_bit x, float_64_bit y) { return std::fabs(x) < std::fabs(y); });
    }

    for (float_64_bit const  lambda : lambdas)
    {
        vecf64  shift;
        if (shift_ptr != nullptr)
        {
            shift = *shift_ptr;
            add_scaled(shift, lambda, space.gradient);
        }
        else
            shift = scale_cp(space.gradient, lambda);
        if (clip_shift_by_constraints(space.constraints, space.gradient, shift))
            resulting_shifts.push_back(shift);
    }

    return !resulting_shifts.empty();
}


bool  chain_minimization_analysis::apply_best_gradient_step()
{
    std::size_t  i_best{ gradient_step_results.size() };
    for (std::size_t  i = 0UL; i < gradient_step_results.size(); ++i)
    {
        {
            ASSUMPTION(gradient_step_results.at(i).values.size() == path.size());
            bool all_finite{ true };
            for (auto const  value : gradient_step_results.at(i).values)
                if (!std::isfinite(value))
                {
                    all_finite = false;
                    break;
                }
            if (!all_finite)
                continue;
        }
        if (i_best == gradient_step_results.size())
        {
            i_best = i;
            continue;
        }

        float_64_bit const  i_best_value{ gradient_step_results.at(i_best).values.back() };
        float_64_bit const  i_value{ gradient_step_results.at(i).values.back() };
        switch (path.back().predicate)
        {
            case BP_EQUAL:
                if (std::fabs(i_value) < std::fabs(path.back().value) && std::fabs(i_value) < std::fabs(i_best_value))
                    i_best = i;
                break;
            case BP_UNEQUAL:
                if (std::fabs(i_value) > std::fabs(path.back().value) && std::fabs(i_value) < std::fabs(i_best_value))
                    i_best = i;
                break;
            case BP_LESS:
            case BP_LESS_EQUAL:
                if (i_value < path.back().value && std::fabs(i_value) < std::fabs(i_best_value))
                    i_best = i;
                break;
            case BP_GREATER:
            case BP_GREATER_EQUAL:
                if (i_value > path.back().value && std::fabs(i_value) < std::fabs(i_best_value))
                    i_best = i;
                break;
            default: { UNREACHABLE(); } break;
        }
    }

    if (i_best == gradient_step_results.size())
        return false;

    progress_stage = PARTIALS;

    gradient_step_result const&  best_result{ gradient_step_results.at(i_best) };

    bits_and_types = best_result.bits_and_types_ptr;
    load_origin(bits_and_types->bits);

    for (std::size_t  i = 0UL; i != path.size(); ++i)
        path.at(i).value = best_result.values.at(i);

    local_spaces.clear();
    insert_first_local_space();

    gradient_step_shifts.clear();
    gradient_step_results.clear();

    return true;
}


void  chain_minimization_analysis::load_origin(vecb const&  bits)
{
    origin.clear();
    origin_in_reals.clear();
    for (std::size_t  i = 0UL, i_end = (natural_32_bit)from_variables_to_input.size(); i != i_end; ++i)
    {
        origin.push_back({});
        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            set_bit((natural_8_bit*)&origin.back(), idx, bits.at(mapping.input_start_bit_index + idx));
        switch (types_of_variables.at(i))
        {
            case type_of_input_bits::BOOLEAN:
                origin_in_reals.push_back((float_64_bit)origin.back()._boolean);
                break;
            case type_of_input_bits::UINT8:
                origin_in_reals.push_back((float_64_bit)origin.back()._uint8);
                break;
            case type_of_input_bits::SINT8:
                origin_in_reals.push_back((float_64_bit)origin.back()._sint8);
                break;
            case type_of_input_bits::UINT16:
                origin_in_reals.push_back((float_64_bit)origin.back()._uint16);
                break;
            case type_of_input_bits::SINT16:
                origin_in_reals.push_back((float_64_bit)origin.back()._sint16);
                break;
            case type_of_input_bits::UINT32:
                origin_in_reals.push_back((float_64_bit)origin.back()._uint32);
                break;
            case type_of_input_bits::SINT32:
                origin_in_reals.push_back((float_64_bit)origin.back()._sint32);
                break;
            case type_of_input_bits::UINT64:
                origin_in_reals.push_back((float_64_bit)origin.back()._uint64);
                break;
            case type_of_input_bits::SINT64:
                origin_in_reals.push_back((float_64_bit)origin.back()._sint64);
                break;
            case type_of_input_bits::FLOAT32:
                origin_in_reals.push_back((float_64_bit)origin.back()._float32);
                break;
            case type_of_input_bits::FLOAT64:
                origin_in_reals.push_back(origin.back()._float64);
                break;
            default: { UNREACHABLE(); }
        }
    }
}


void  chain_minimization_analysis::store_shifted_origin(vecb&  bits)
{
    bits = bits_and_types->bits;
    for (std::size_t  i = 0ULL; i != origin.size(); ++i)
    {
        typed_value_storage  value{ origin.at(i) };
        float_64_bit const  delta{ at(local_spaces.front().sample_shift, i) };
        switch (types_of_variables.at(i))
        {
            case type_of_input_bits::BOOLEAN:
                value._boolean = std::fabs(delta) < 0.5 ? false : true;
                break;
            case type_of_input_bits::UINT8:
                value._uint8 = (natural_8_bit)((integer_8_bit)value._uint8 + (integer_8_bit)std::round(delta));
                break;
            case type_of_input_bits::SINT8:
                value._sint8 += (integer_8_bit)std::round(delta);
                break;
            case type_of_input_bits::UINT16:
                value._uint16 = (natural_16_bit)((integer_16_bit)value._uint16 + (integer_16_bit)std::round(delta));
                break;
            case type_of_input_bits::SINT16:
                value._sint16 += (integer_16_bit)std::round(delta);
                break;
            case type_of_input_bits::UINT32:
                value._uint32 = (natural_32_bit)((integer_32_bit)value._uint32 + (integer_32_bit)std::round(delta));
                break;
            case type_of_input_bits::SINT32:
                value._sint32 += (integer_32_bit)std::round(delta);
                break;
            case type_of_input_bits::UINT64:
                value._uint64 = (natural_64_bit)((integer_64_bit)value._uint64 + (integer_64_bit)std::round(delta));
                break;
            case type_of_input_bits::SINT64:
                value._sint64 += (integer_64_bit)std::round(delta);
                break;
            case type_of_input_bits::FLOAT32:
                value._float32 += (float_32_bit)delta;
                break;
            case type_of_input_bits::FLOAT64:
                value._float64 += delta;
                break;
            default: { UNREACHABLE(); }
        }

        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            bits.at(mapping.input_start_bit_index + idx) = get_bit((natural_8_bit const*)&value, idx);
    }
}


}
