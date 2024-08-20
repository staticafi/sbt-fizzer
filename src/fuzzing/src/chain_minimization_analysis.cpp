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
    , tested_origins{ &types_of_variables }
    , local_spaces{}
    , gradient_step_shifts{}
    , gradient_step_results{}
    , recovery{}
    , stability{}
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

    bits_to_point(bits_and_types->bits, origin);

    local_spaces.clear();
    insert_first_local_space();

    tested_origins.clear();

    gradient_step_shifts.clear();
    gradient_step_results.clear();

    recovery = {};
    stability = {};

    tested_origins.insert(make_vector_overlay(origin, types_of_variables));

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

            if (local_spaces.size() != path.size())
            {
                stop_with_failure();
                return false;
            }

            INVARIANT(size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis));

            gradient_step_shifts.clear();
            gradient_step_results.clear();
            if (!compute_gradient_step_shifts(gradient_step_shifts, local_spaces.size() - 1UL, path.back().value, nullptr))
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
            else if (compute_stability_shift_for_origin())
                progress_stage = STABILITY;
            else
            {
                stop_with_failure();
                return false;
            }
        }
        else if (progress_stage == RECOVERY)
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
        else if (progress_stage == STABILITY)
        {
            if (stability.step_index >= gradient_step_shifts.size())
            {
                stop_with_failure();
                return false;
            }
            local_spaces.back().sample_shift = stability.shift;
            transform_shift(local_spaces.size() - 1UL);
            break;
        }
        else { UNREACHABLE(); }
    }

    vecf64 const  shifted_origin{ add_cp(origin, local_spaces.front().sample_shift) };
    vector_overlay const  shifted_origin_overlay{ point_to_bits(shifted_origin, bits_ref) };
    tested_origins.insert(shifted_origin_overlay);

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
            recovery.space_index = last_index;
            recovery.shift = local_spaces.at(last_index).sample_shift;
            recovery.value = local_spaces.at(last_index).sample_value;
            compute_gradient_step_shifts(
                    recovery.sample_shifts,
                    recovery.space_index,
                    recovery.value,
                    &recovery.shift
                    );
            std::reverse(recovery.sample_shifts.begin(), recovery.sample_shifts.end());

            progress_stage = RECOVERY;
        }
        else
        {
            if (recovery.space_index == last_index)
            {
                if (std::fabs(local_spaces.at(recovery.space_index).sample_value) <= std::fabs(recovery.value))
                {
                    recovery.shift = local_spaces.at(last_index).sample_shift;
                    recovery.value = local_spaces.at(last_index).sample_value;
                    std::size_t const  old_size{ recovery.sample_shifts.size() };
                    compute_gradient_step_shifts(
                            recovery.sample_shifts,
                            recovery.space_index,
                            recovery.value,
                            &recovery.shift
                            );
                    std::reverse(std::next(recovery.sample_shifts.begin(), old_size), recovery.sample_shifts.end());
                }
            }
            else if (recovery.space_index < last_index)
            {
                recovery.space_index = last_index;
                recovery.shift = local_spaces.at(last_index).sample_shift;
                recovery.value = local_spaces.at(last_index).sample_value;
                recovery.sample_shifts.clear();
                compute_gradient_step_shifts(
                        recovery.sample_shifts,
                        recovery.space_index,
                        recovery.value,
                        &recovery.shift
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

                    gradient_step_shifts.clear();
                    gradient_step_results.clear();
                    compute_gradient_step_shifts(gradient_step_shifts, local_spaces.size() - 1UL, path.back().value, nullptr);
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
            // Nothing to do.
            break;
        case STABILITY:
            {
                std::vector<float_64_bit>  values;
                for (auto const&  space : local_spaces)
                    values.push_back(space.sample_value);
                commit_execution_results(bits_and_types_ptr, values);
                if (std::equal(origin.cbegin(), origin.cend(), stability.origin_backup.cbegin()))
                    stability = {}; // We failed to stabilize the computation by shifting the origin towards the zero vector.
                else
                    progress_stage = PARTIALS;
            }
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
            for (natural_32_bit  var_idx : space.variable_indices.at(partial_index))
                if (path.at(space_index).variable_indices.contains(var_idx))
                {
                    has_sensitive_var = true;
                    break;
                }
            if (has_sensitive_var)
            {
                vecf64  shift;
                axis(shift, columns(space.orthogonal_basis), partial_index);

                float_64_bit  param;
                {
                    float_64_bit constexpr  coef{ 0.01 };
                    float_64_bit const  value{ (1.0 - coef) * max_abs(origin) + coef * std::fabs(path.at(space_index).value) };
                    param = small_delta_around(value);
                    param /= at(space.scales_of_basis_vectors_in_world_space, partial_index);
                }

                origin_set  ignore_origin{ &types_of_variables };
                ignore_origin.insert(make_vector_overlay(origin, types_of_variables));

                float_64_bit const  lambda{
                        compute_best_shift_along_ray(origin, at(space.basis_vectors_in_world_space, partial_index), param, ignore_origin)
                        };
                if (lambda != 0.0)
                {
                    space.sample_shift = scale_cp(shift, lambda);

                    if (are_constraints_satisfied(space.constraints, space.sample_shift))
                        return true;

                    negate(space.sample_shift);

                    if (are_constraints_satisfied(space.constraints, space.sample_shift))
                        return true;
                }
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


void  chain_minimization_analysis::transform_shift(std::size_t const  src_space_index) const
{
    ASSUMPTION(src_space_index < local_spaces.size());
    for (std::size_t  i = src_space_index; i > 0UL; --i)
    {
        vecf64&  shift{ local_spaces.at(i - 1UL).sample_shift };
        set(shift, 0.0);
        local_space_of_branching const&  space{ local_spaces.at(i) };
        for (std::size_t  j = 0UL; j < columns(space.orthogonal_basis); ++j)
            add_scaled(shift, at(space.sample_shift, j), column(space.orthogonal_basis, j));
    }
}


vecf64 const&  chain_minimization_analysis::transform_shift(vecf64 const&  shift, std::size_t const  src_space_index) const
{
    ASSUMPTION(src_space_index < local_spaces.size());
    local_spaces.at(src_space_index).sample_shift = shift;
    transform_shift(src_space_index);
    return local_spaces.front().sample_shift;
}


void  chain_minimization_analysis::transform_shift_back(std::size_t const  dst_space_index) const
{
    ASSUMPTION(dst_space_index < local_spaces.size());
    for (std::size_t  i = 0UL; i < dst_space_index; ++i)
    {
        vecf64 const&  shift{ local_spaces.at(i).sample_shift };
        local_space_of_branching const&  space{ local_spaces.at(i + 1UL) };
        for (std::size_t  j = 0UL; j < columns(space.orthogonal_basis); ++j)
            at(space.sample_shift, j) = dot_product(shift, at(space.orthogonal_basis, j)) /
                                        dot_product(at(space.orthogonal_basis, j), at(space.orthogonal_basis, j));
    }

}


vecf64 const&  chain_minimization_analysis::transform_shift_back(vecf64 const&  shift, std::size_t  dst_space_index) const
{
    ASSUMPTION(dst_space_index < local_spaces.size());
    local_spaces.front().sample_shift = shift;
    transform_shift_back(dst_space_index);
    return local_spaces.at(dst_space_index).sample_shift;
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
    local_spaces.back().basis_vectors_in_world_space = local_spaces.back().orthogonal_basis;
    reset(local_spaces.back().scales_of_basis_vectors_in_world_space, columns(local_spaces.back().orthogonal_basis), 1.0);
    reset(local_spaces.back().sample_shift, columns(local_spaces.back().orthogonal_basis), 0.0);
}


void  chain_minimization_analysis::insert_next_local_space()
{
    ASSUMPTION(local_spaces.size() < path.size() && size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis));

    local_spaces.push_back({});

    auto const src_space_index{ local_spaces.size() - 2UL };
    auto const dst_space_index{ local_spaces.size() - 1UL };
    local_space_of_branching const&  src_space{ local_spaces.at(src_space_index) };
    local_space_of_branching&  dst_space{ local_spaces.at(dst_space_index) };

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
        dst_space.basis_vectors_in_world_space = src_space.basis_vectors_in_world_space;
        dst_space.scales_of_basis_vectors_in_world_space = src_space.scales_of_basis_vectors_in_world_space;
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

    auto const& push_back_basis_vector_props_in_world_space = [this, src_space_index, &src_space, &dst_space] (vecf64 const&  basis_vector) -> void {
        dst_space.basis_vectors_in_world_space.push_back(this->transform_shift(basis_vector, src_space_index));
        dst_space.scales_of_basis_vectors_in_world_space.push_back( max_abs(dst_space.basis_vectors_in_world_space.back()) );
        INVARIANT(dst_space.scales_of_basis_vectors_in_world_space.back() > 1e-9);
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
            push_back_basis_vector_props_in_world_space(w);
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
                push_back_basis_vector_props_in_world_space(w);
            }
        }
    }

    branching_info const&  src_info{ path.at(src_space_index) };
    if (src_info.predicate != BP_EQUAL)
    {
        dst_space.orthogonal_basis.push_back(src_space.gradient);
        collect_variable_indices_for_last_basis_vector();
        push_back_basis_vector_props_in_world_space(dst_space.orthogonal_basis.back());
        vecf64  normal;
        axis(normal, columns(dst_space.orthogonal_basis), columns(dst_space.orthogonal_basis) - 1UL);
        dst_space.constraints.push_back({
            normal,
            -src_info.value * gg_inv,
            src_info.predicate
        });
    }

    if (dst_space.orthogonal_basis.empty())
        return;

    for (spatial_constraint const&  constraint : src_space.constraints)
    {
        vecf64  normal;
        for (vecf64 const&  u : dst_space.orthogonal_basis)
            normal.push_back(dot_product(constraint.normal, u) / dot_product(u, u));
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
                if (!(param != constraint.param))
                    return false;
                break;
            case BP_LESS:
                if (!(param < constraint.param))
                    return false;
                break;
            case BP_LESS_EQUAL:
                if (!(param <= constraint.param))
                    return false;
                break;
            case BP_GREATER:
                if (!(param > constraint.param))
                    return false;
                break;
            case BP_GREATER_EQUAL:
                if (!(param >= constraint.param))
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
            vecf64  direction{ constraint.normal };
            if (iteration == 0UL)
            {
                vecf64 const  component{ component_of_first_orthogonal_to_second(constraint.normal, gradient) };
                if (dot_product(component, component) >= 0.01 * dot_product(constraint.normal, constraint.normal))
                {
                    direction = component;
                    scale(direction, dot_product(constraint.normal, constraint.normal) / dot_product(direction, constraint.normal));
                }
            }
            float_64_bit const  param{ dot_product(shift, constraint.normal) / dot_product(constraint.normal, constraint.normal) };
            float_64_bit const  epsilon{ small_delta_around(param) };
            switch (constraint.predicate)
            {
                case BP_UNEQUAL:
                    if (!(constraint.param != param))
                    {
                        add_scaled(shift, (constraint.param + epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BP_LESS:
                    if (!(param < constraint.param))
                    {
                        add_scaled(shift, (constraint.param - epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BP_LESS_EQUAL:
                    if (!(param <= constraint.param))
                    {
                        add_scaled(shift, constraint.param - param, direction);
                        clipped = true;
                    }
                    break;
                case BP_GREATER:
                    if (!(param > constraint.param))
                    {
                        add_scaled(shift, (constraint.param + epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BP_GREATER_EQUAL:
                    if (!(param >= constraint.param))
                    {
                        add_scaled(shift, constraint.param - param, direction);
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


bool  chain_minimization_analysis::compute_gradient_step_shifts(
        std::vector<vecf64>&  resulting_shifts,
        std::size_t const  space_index,
        float_64_bit const  value,
        vecf64 const* const  shift_ptr
        )
{
    local_space_of_branching const&  space{ local_spaces.at(space_index) };
    comparator_type const  predicate{ path.at(space_index).predicate };

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

    std::vector<float_64_bit>  lambdas;
    {
        vecf64 const  ray_dir{ transform_shift(space.gradient, space_index) };

        vecf64  ray_start;
        if (shift_ptr == nullptr)
            ray_start = add_scaled_cp(origin, lambda0, ray_dir);
        else
            ray_start = add_scaled_cp(add_cp(origin, transform_shift(*shift_ptr, space_index)), lambda0, ray_dir);

        float_64_bit  param;
        {
            float_64_bit constexpr  coef{ 0.01 };
            float_64_bit const  value{ (1.0 - coef) * max_abs(ray_start) + coef * std::fabs(path.at(space_index).value) };
            param = small_delta_around(value);
            param /= length(ray_dir);
        }

        origin_set  ignored_points{ tested_origins };
        ignored_points.insert(make_vector_overlay(ray_start, types_of_variables));

        switch (predicate)
        {
            case BP_EQUAL:
                ASSUMPTION(value != 0.0 && lambda0 != 0.0);
                lambdas.push_back(lambda0);
                break;
            case BP_UNEQUAL:
                ASSUMPTION(value == 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_LESS:
                ASSUMPTION(value >= 0.0 && lambda0 <= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_LESS_EQUAL:
                ASSUMPTION(value > 0.0 && lambda0 < 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_GREATER:
                ASSUMPTION(value <= 0.0 && lambda0 >= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            case BP_GREATER_EQUAL:
                ASSUMPTION(value < 0.0 && lambda0 > 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            default: { UNREACHABLE(); } break;
        }
    }

    origin_set  used_origins{ &types_of_variables };
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

        if (!clip_shift_by_constraints(space.constraints, space.gradient, shift))
            continue;

        vecf64 const  point{ add_cp(origin, transform_shift(shift, space_index)) };
        vector_overlay const  point_overlay{ make_vector_overlay(point, types_of_variables) };

        if (tested_origins.contains(point_overlay) || used_origins.contains(point_overlay))
            continue;

        resulting_shifts.push_back(shift);
        used_origins.insert(point_overlay);
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

        float_64_bit const  i_value{ gradient_step_results.at(i).values.back() };

        {
            bool  is_improving{ false };
            switch (path.back().predicate)
            {
                case BP_EQUAL:
                    if (std::fabs(i_value) < std::fabs(path.back().value))
                        is_improving = true;
                    break;
                case BP_UNEQUAL:
                    if (std::fabs(i_value) > std::fabs(path.back().value))
                        is_improving = true;
                    break;
                case BP_LESS:
                case BP_LESS_EQUAL:
                    if (i_value < path.back().value)
                        is_improving = true;
                    break;
                case BP_GREATER:
                case BP_GREATER_EQUAL:
                    if (i_value > path.back().value)
                        is_improving = true;
                    break;
                default: { UNREACHABLE(); } break;
            }
            if (!is_improving)
                continue;
        }

        if (i_best == gradient_step_results.size())
        {
            i_best = i;
            continue;
        }

        float_64_bit const  i_best_value{ gradient_step_results.at(i_best).values.back() };
        if (std::fabs(i_value) < std::fabs(i_best_value))
            i_best = i;
    }

    if (i_best == gradient_step_results.size())
        return false;

    gradient_step_result const&  best_result{ gradient_step_results.at(i_best) };
    commit_execution_results(best_result.bits_and_types_ptr, best_result.values);

    return true;
}


float_64_bit  chain_minimization_analysis::compute_best_shift_along_ray(
        vecf64 const&  ray_start,
        vecf64  ray_dir,
        float_64_bit  param,
        origin_set const&  excluded_points
        ) const
{
    ASSUMPTION(size(ray_start) == size(ray_dir) && size(ray_start) == types_of_variables.size());

    float_64_bit  sign{ 1.0 };
    if (param < 0.0)
    {
        param = -param;
        negate(ray_dir);
        sign = -1.0;
    }

    float_64_bit const  dd{ dot_product(ray_dir, ray_dir) };
    float_64_bit  dd_inv{ 1.0 / dd };
    if (!std::isfinite(dd_inv) || std::isnan(dd_inv))
        dd_inv = std::numeric_limits<float_64_bit>::infinity();

    using  error_and_param = std::pair<float_64_bit, float_64_bit>;
    std::vector<error_and_param>  samples;

    vecf64  point{ ray_start };
    add_scaled(point, param, ray_dir);

    vecf64  ray_dir_inv{ invert(ray_dir) };
    for (float_64_bit& x : ray_dir_inv)
        if (!std::isfinite(x) || std::isnan(x))
            x = std::numeric_limits<float_64_bit>::infinity();

    for (std::size_t  iter = 0UL, max_num_samples = 2UL * size(ray_start); iter != max_num_samples; ++iter)
    {
        vecf64 const  steps{ smallest_step(point, types_of_variables, ray_dir) };
        vecf64 const  params{ modulate(steps, ray_dir_inv) };
        param = *std::min_element(params.begin(), params.end());
        if (!std::isfinite(param) || std::isnan(param))
            break;

        add_scaled(point, param, ray_dir);

        vector_overlay  point_overlay{ make_vector_overlay(point, types_of_variables) };
        if (!excluded_points.contains(point_overlay))
        {
            vecf64 const  diff{ sub_cp(as<float_64_bit>(point_overlay, types_of_variables), point) };
            vecf64 const  error{ add_scaled_cp(diff, -dot_product(ray_dir, diff) * dd_inv, ray_dir) };
            samples.push_back({
                    dot_product(error, error),
                    dot_product(ray_dir, sub_cp(point, ray_start)) * dd_inv
                    });
        }
    }
    std::sort(samples.begin(), samples.end());
    return samples.empty() ? 0.0 : sign * samples.front().second;
}


bool  chain_minimization_analysis::compute_stability_shift_for_origin()
{
    stability = {};
    stability.origin_backup = origin;

    for (std::size_t  i = 0UL; i < gradient_step_results.size(); ++i)
    {
        vecf64  origin_i;
        bits_to_point(gradient_step_results.at(i).bits_and_types_ptr->bits, origin_i);
        if (std::equal(origin_i.cbegin(), origin_i.cend(), origin.cbegin()))
        {
            stability.step_index = i;
            break;
        }
    }

    if (stability.step_index >= gradient_step_results.size())
        return false;

    // TODO: 
    //  1. transform origin to local_spaces.back().orthogonal_basis and denote it as S.
    //  2. Update the code below to find the shift to S.

    float_64_bit const  gg_inv{ 1.0 / dot_product(local_spaces.back().gradient, local_spaces.back().gradient) };
    float_64_bit const  gO{ dot_product(local_spaces.back().gradient, stability.origin_backup) };
    stability.shift = gradient_step_shifts.at(stability.step_index);
    add_scaled(stability.shift, gO * gg_inv, local_spaces.back().gradient);
    add_scaled(stability.shift, -1, stability.origin_backup);

    //  3. Clip the shipt according to the constraints in local_spaces.back().constraints.

    return true;
}


void  chain_minimization_analysis::commit_execution_results(
        stdin_bits_and_types_pointer const  bits_and_types_ptr,
        std::vector<float_64_bit> const&  values
        )
{
    bits_and_types = bits_and_types_ptr;
    bits_to_point(bits_and_types->bits, origin);

    for (std::size_t  i = 0UL; i != path.size(); ++i)
        path.at(i).value = values.at(i);

    local_spaces.clear();
    insert_first_local_space();

    gradient_step_shifts.clear();
    gradient_step_results.clear();
}


void  chain_minimization_analysis::bits_to_point(vecb const&  bits, vecf64&  point)
{
    point.clear();
    for (std::size_t  i = 0UL, i_end = (natural_32_bit)from_variables_to_input.size(); i != i_end; ++i)
    {
        number_overlay  value;
        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            set_bit((natural_8_bit*)&value, idx, bits.at(mapping.input_start_bit_index + idx));
        point.push_back(as<float_64_bit>(value, types_of_variables.at(i)));
    }
}


vector_overlay  chain_minimization_analysis::point_to_bits(vecf64 const&  point, vecb&  bits)
{
    vector_overlay const  point_overlay{ make_vector_overlay(point, types_of_variables) };
    bits = bits_and_types->bits;
    for (std::size_t  i = 0ULL; i != point_overlay.size(); ++i)
    {
        mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        for (natural_8_bit  idx : mapping.value_bit_indices)
            bits.at(mapping.input_start_bit_index + idx) = get_bit((natural_8_bit const*)&point_overlay.at(i), idx);
    }
    return point_overlay;
}


}
