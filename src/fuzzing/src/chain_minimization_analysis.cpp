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
    , max_executions{ 0U }
    , progress_stage{ PARTIALS }
    , origin{}
    , tested_origins{ &types_of_variables }
    , local_spaces{}
    , partials_props{}
    , descent_props{}
    , recovery_props{}
    , rnd_generator{}
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
    types_of_variables.clear();
    from_variables_to_input.clear();
    stopped_early = false;
    num_executions = 0U;
    max_executions = 0U;

    progress_stage = PARTIALS;
    origin.clear();
    tested_origins.clear();
    local_spaces.clear();
    partials_props = {};
    descent_props = {};
    recovery_props = {};

    reset(rnd_generator);

    path.push_back({
            node,
            node->best_trace->at(node->trace_index).value,
            node->is_direction_unexplored(false) ? false : true,
            node->is_direction_unexplored(false) ? opposite_predicate(node->branching_predicate) : node->branching_predicate,
            node->xor_like_branching_function,
            {}
            });
    for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
        path.push_back({
                n,
                node->best_trace->at(n->trace_index).value,
                n->successor_direction(s),
                n->successor_direction(s) ? n->branching_predicate : opposite_predicate(n->branching_predicate),
                n->xor_like_branching_function,
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

    {
        natural_32_bit  nbits{ 0U };
        for (type_identifier const tid : types_of_variables)
            nbits += num_bits(tid);

        max_executions = (natural_32_bit)std::round((float_64_bit)(100U * nbits) + std::pow((float_64_bit)(path.size() + 2U), 2.5));
    }

    bits_to_point(bits_and_types->bits, origin);
    tested_origins.insert(make_vector_overlay(origin, types_of_variables));

    insert_first_local_space();

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
            if (partials_props.shifts.empty())
                compute_shifts_of_next_partial();

            if (!partials_props.shifts.empty())
            {
                local_spaces.back().sample_shift = partials_props.shifts.back();
                partials_props.shifts.pop_back();
                transform_shift(local_spaces.size() - 1UL);
                break;
            }

            if (local_spaces.size() != path.size())
            {
                stop_with_failure();
                return false;
            }

            INVARIANT(size(local_spaces.back().gradient) == columns(local_spaces.back().orthogonal_basis));

            descent_props.clear();
            if (!compute_descent_shifts(descent_props.shifts, local_spaces.size() - 1UL, path.back().value, nullptr))
            {
                stop_with_failure();
                return false;
            }

            progress_stage = DESCENT;
        }
        else if (progress_stage == DESCENT)
        {
            if (descent_props.results.size() < descent_props.shifts.size())
            {
                local_spaces.back().sample_shift = descent_props.shifts.at(descent_props.results.size());
                transform_shift(local_spaces.size() - 1UL);
                break;
            }
            if (!apply_best_gradient_step())
            {
                stop_with_failure();
                return false;
            }

            progress_stage = PARTIALS;
        }
        else if (progress_stage == RECOVERY)
        {
            if (!recovery_props.sample_shifts.empty())
            {
                local_spaces.at(recovery_props.space_index).sample_shift = recovery_props.sample_shifts.back();
                recovery_props.sample_shifts.pop_back();
                transform_shift(recovery_props.space_index);
                break;
            }

            if (recovery_props.stage_backup == PARTIALS)
            {
                INVARIANT(size(local_spaces.back().gradient) < size(local_spaces.back().orthogonal_basis));
                if (partials_props.shifts.empty())
                    local_spaces.back().gradient.push_back(0.0);
            }
            else if (recovery_props.stage_backup == DESCENT)
            {
                INVARIANT(descent_props.results.size() < descent_props.shifts.size());
                descent_props.results.push_back({ nullptr, {} });
                reset(descent_props.results.back().values, local_spaces.size(), INFINITY);
            }
            else
            {
                stop_with_failure();
                return false;
            }

            progress_stage = recovery_props.stage_backup;
        }
        else { UNREACHABLE(); }
    }

    vecf64 const  shifted_origin{ add_cp(origin, local_spaces.front().sample_shift) };
    ASSUMPTION(isfinite(shifted_origin));
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

    bool  unexpected_node_id{ false };
    std::size_t  last_index{ 0UL };
    for (std::size_t const  n = std::min({ local_spaces.size(), trace_ptr->size() }); last_index != n; ++last_index)
    {
        if (trace_ptr->at(last_index).id != path.at(last_index).node_ptr->id)
        {
            unexpected_node_id = true;
            break;
        }
        local_spaces.at(last_index).sample_value = cast_float_value<float_64_bit>(trace_ptr->at(last_index).value);
        if (last_index < local_spaces.size() - 1UL && trace_ptr->at(last_index).direction != path.at(last_index).direction)
            break;
    }

    if (last_index != local_spaces.size())
    {
        bool const  unexpected_early_termination{ last_index == trace_ptr->size() };
        bool const  is_recoverable{ !unexpected_node_id && !unexpected_early_termination };
        if (progress_stage != RECOVERY)
        {
            recovery_props.stage_backup = progress_stage;
            recovery_props.space_index = last_index;
            recovery_props.shift = local_spaces.at(last_index).sample_shift;
            recovery_props.value = local_spaces.at(last_index).sample_value;
            recovery_props.sample_shifts.clear();
            if (is_recoverable)
            {
                compute_descent_shifts(
                        recovery_props.sample_shifts,
                        recovery_props.space_index,
                        recovery_props.value,
                        &recovery_props.shift
                        );
                std::reverse(recovery_props.sample_shifts.begin(), recovery_props.sample_shifts.end());
            }

            progress_stage = RECOVERY;
        }
        else if (is_recoverable)
        {
            if (recovery_props.space_index == last_index)
            {
                if (std::fabs(local_spaces.at(recovery_props.space_index).sample_value) < std::fabs(recovery_props.value))
                {
                    recovery_props.shift = local_spaces.at(last_index).sample_shift;
                    recovery_props.value = local_spaces.at(last_index).sample_value;
                    recovery_props.sample_shifts.clear();
                    compute_descent_shifts(
                            recovery_props.sample_shifts,
                            recovery_props.space_index,
                            recovery_props.value,
                            &recovery_props.shift
                            );
                    std::reverse(recovery_props.sample_shifts.begin(), recovery_props.sample_shifts.end());
                }
            }
            else if (recovery_props.space_index < last_index)
            {
                recovery_props.space_index = last_index;
                recovery_props.shift = local_spaces.at(last_index).sample_shift;
                recovery_props.value = local_spaces.at(last_index).sample_value;
                recovery_props.sample_shifts.clear();
                compute_descent_shifts(
                        recovery_props.sample_shifts,
                        recovery_props.space_index,
                        recovery_props.value,
                        &recovery_props.shift
                        );
                std::reverse(recovery_props.sample_shifts.begin(), recovery_props.sample_shifts.end());
            }
        }
    }
    else if (progress_stage == RECOVERY)
    {
        if (recovery_props.stage_backup == DESCENT)
        {
            transform_shift_back(local_spaces.size() - 1UL);
            descent_props.shifts.at(descent_props.results.size()) = local_spaces.back().sample_shift;
        }

        progress_stage = recovery_props.stage_backup;
    }

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
                    progress_stage = DESCENT;

                    descent_props.clear();
                    compute_descent_shifts(descent_props.shifts, local_spaces.size() - 1UL, path.back().value, nullptr);
                }
            }
            ++statistics.partials;
            break;
        case DESCENT:
            if (descent_props.results.size() < descent_props.shifts.size())
            {
                descent_props.results.push_back({ bits_and_types_ptr, {} });
                for (auto const&  space : local_spaces)
                    descent_props.results.back().values.push_back(space.sample_value);
            }
            ++statistics.gradient_steps;
            break;
        case RECOVERY:
            // Nothing to do.
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


void  chain_minimization_analysis::compute_shifts_of_next_partial()
{
    ASSUMPTION(partials_props.shifts.empty());
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
                vecf64  params;
                {
                    float_64_bit const param {
                            small_delta_around(max_abs(origin)) / at(space.scales_of_basis_vectors_in_world_space, partial_index)
                            };
                    params.push_back(param);
                    params.push_back(-param);

                    int  exponent;
                    std::frexp(param, &exponent);
                    int constexpr  num_float32_digits{ std::numeric_limits<float_32_bit>::digits };
                    for (exponent += num_float32_digits; exponent < 0; exponent += num_float32_digits)
                        params.push_back(std::pow(2.0, exponent));

                    std::reverse(params.begin(), params.end());
                }

                origin_set  ignore_origin{ &types_of_variables };
                ignore_origin.insert(make_vector_overlay(origin, types_of_variables));

                std::vector<vecf64>  shifts;
                for (float_64_bit const  param : params)
                {
                    float_64_bit const  lambda{
                            compute_best_shift_along_ray(origin, at(space.basis_vectors_in_world_space, partial_index), param, ignore_origin)
                            };

                    vecf64  shift;
                    axis(shift, columns(space.orthogonal_basis), partial_index);
                    scale(shift, lambda);

                    if (isfinite(shift))
                    {
                        if (are_constraints_satisfied(space.constraints, shift))
                            shifts.push_back(shift);
                        else
                        {
                            negate(shift);
                            if (are_constraints_satisfied(space.constraints, shift))
                                shifts.push_back(shift);
                        }
                    }
                }

                for (vecf64 const&  shift : shifts)
                {
                    vecf64 const  point{ add_cp(origin, transform_shift(shift, space_index)) };
                    if (isfinite(point))
                        partials_props.shifts.push_back(shift);
                }

                if (!partials_props.shifts.empty())
                    return;
            }

            space.gradient.push_back(0.0);
        }

        if (local_spaces.size() < path.size())
            insert_next_local_space();
    }
}


void  chain_minimization_analysis::compute_partial_derivative()
{
    local_space_of_branching&  space{ local_spaces.back() };
    ASSUMPTION(size(space.gradient) < columns(space.orthogonal_basis));
    float_64_bit const partial{ (space.sample_value - path.at(local_spaces.size() - 1UL).value) / at(space.sample_shift, size(space.gradient)) };
    if (!std::isfinite(partial) || std::isnan(partial) || partial == 0.0)
    {
        if (partials_props.shifts.empty())
            space.gradient.push_back(0.0);
    }
    else
    {
        space.gradient.push_back(partial);
        partials_props.clear();
    }
}


void  chain_minimization_analysis::transform_shift(std::size_t const  src_space_index) const
{
    ASSUMPTION(src_space_index < local_spaces.size() && isfinite(local_spaces.at(src_space_index).sample_shift));
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
    ASSUMPTION(dst_space_index < local_spaces.size() && isfinite(local_spaces.front().sample_shift));
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
        float_64_bit const  scale{
            dot_product(constraint.normal, constraint.normal) / dot_product(constraint.normal, mul(dst_space.orthogonal_basis, normal))
        };
        float_64_bit const  param{ cast_float_value<float_64_bit>(constraint.param * scale) };
        if (std::isfinite(param) && !std::isnan(param))
            dst_space.constraints.push_back({ normal, param, constraint.predicate });
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
            float_64_bit  param{ dot_product(shift, constraint.normal) / dot_product(constraint.normal, constraint.normal) };
            if (!std::isfinite(param) || std::isnan(param))
                return false;

            float_64_bit const  epsilon{ small_delta_around(cast_float_value<float_64_bit>(param)) };
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


bool  compute_gg_inv_and_lambda0(vecf64 const& g, float_64_bit const  value, float_64_bit&  gg_inv, float_64_bit&  lambda0) {
    gg_inv = 1.0 / dot_product(g, g);
    lambda0 = -value * gg_inv;
    if (!std::isfinite(gg_inv) || std::isnan(gg_inv) || !std::isfinite(lambda0) || std::isnan(lambda0))
        return false;
    for (auto const coord : g)
    {
        float_64_bit const  x{ coord * lambda0 };
        if (!std::isfinite(x) || std::isnan(x))
            return false;
    }
    return true;
}


bool  chain_minimization_analysis::compute_descent_shifts(
        std::vector<vecf64>&  resulting_shifts,
        std::size_t const  space_index,
        float_64_bit const  value,
        vecf64 const* const  shift_ptr
        )
{
    vecf64 const  grad_orig{ local_spaces.at(space_index).gradient };

    std::vector<vecf64>  gradients;
    {
        float_64_bit gg_inv, lambda0;
        if (!compute_gg_inv_and_lambda0(grad_orig, value, gg_inv, lambda0))
        {
            gradients.push_back({});
            for (std::size_t  i = 0UL; i < size(grad_orig); ++i)
                gradients.back().push_back(get_random_integer_32_bit_in_range(-10001, 10000, rnd_generator) < 0 ? -1.0 : 1.0);
        }
        else
        {
            gradients.push_back(grad_orig);
            if (path.at(space_index).xor_like_branching_function)
            {
                gradients.push_back(negate_cp(grad_orig));
                gradients.push_back(scale_cp(grad_orig, +1.0 / max_abs(grad_orig)));
                gradients.push_back(scale_cp(grad_orig, -1.0 / max_abs(grad_orig)));
            }
        }
    }

    origin_set  used_origins{ &types_of_variables };
    for (vecf64 const&  grad : gradients)
        compute_descent_shifts(resulting_shifts, space_index, grad, value, used_origins, shift_ptr);

    if (!gradients.empty() && (max_abs(origin) > 1e20 ||
                               has_high_extreme_coordinate(make_vector_overlay(origin, types_of_variables), types_of_variables)))
    {
        vecf64 const  T{ transform_shift_back(origin, space_index) };
        vecf64  shift{ scale_cp(T, -1.0) };

        clip_shift_by_constraints(local_spaces.at(space_index).constraints, gradients.front(), shift);

        if (isfinite(shift))
        {
            vecf64 const  point{ add_cp(origin, transform_shift(shift, space_index)) };
            vector_overlay const  point_overlay{ make_vector_overlay(point, types_of_variables) };
            if (is_finite(point_overlay, types_of_variables) && !tested_origins.contains(point_overlay) && !used_origins.contains(point_overlay))
                resulting_shifts.push_back(shift);
        }
    }

    return !resulting_shifts.empty();
}


void  chain_minimization_analysis::compute_descent_shifts(
        std::vector<vecf64>&  resulting_shifts,
        std::size_t const  space_index,
        vecf64 const&  grad,
        float_64_bit  value,
        origin_set&  used_origins,
        vecf64 const*  shift_ptr
        )
{
    local_space_of_branching const&  space{ local_spaces.at(space_index) };
    comparator_type const  predicate{ path.at(space_index).predicate };

    for (std::size_t  i = 0UL; i <= size(grad); ++i)
    {
        vecf64  g{ grad };
        if (i != 0UL)
        {
            if (at(g, i - 1UL) == 0.0)
                continue;
            at(g, i - 1UL) = 0.0;
        }

        float_64_bit gg_inv, lambda0;
        if (!compute_gg_inv_and_lambda0(g, value, gg_inv, lambda0))
            continue;
    
        vecf64  lambdas;
        {
            vecf64 const  ray_dir{ transform_shift(g, space_index) };

            vecf64  ray_start;
            if (shift_ptr == nullptr)
                ray_start = add_scaled_cp(origin, lambda0, ray_dir);
            else
                ray_start = add_scaled_cp(add_cp(origin, transform_shift(*shift_ptr, space_index)), lambda0, ray_dir);

            float_64_bit  param;
            {
                float_64_bit constexpr  coef{ 0.01 };
                float_64_bit const  value{ (1.0 - coef) * max_abs(ray_start) + coef * std::fabs(path.at(space_index).value) };
                param = small_delta_around(cast_float_value<float_64_bit>(value));
                param /= length(ray_dir);
            }

            origin_set  ignored_points{ tested_origins };
            ignored_points.insert(make_vector_overlay(ray_start, types_of_variables));

            switch (predicate)
            {
                case BP_EQUAL:
                    ASSUMPTION(value != 0.0);// && lambda0 != 0.0);
                    lambdas.push_back(lambda0);
                    break;
                case BP_UNEQUAL:
                    ASSUMPTION(value == 0.0);
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                    break;
                case BP_LESS:
                    ASSUMPTION(value >= 0.0);// && lambda0 <= 0.0);
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                    break;
                case BP_LESS_EQUAL:
                    ASSUMPTION(value > 0.0);// && lambda0 < 0.0);
                    lambdas.push_back(lambda0);
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                    break;
                case BP_GREATER:
                    ASSUMPTION(value <= 0.0);// && lambda0 >= 0.0);
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                    break;
                case BP_GREATER_EQUAL:
                    ASSUMPTION(value < 0.0);// && lambda0 > 0.0);
                    lambdas.push_back(lambda0);
                    lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                    break;
                default: { UNREACHABLE(); } break;
            }

            static vecf64 const multipliers {
                1000.0,
                100.0,
                10.0,
                1.0,
                0.1,
                0.01,
                0.001,
                };
            for (float_64_bit const  m : multipliers)
                lambdas.push_back(m * lambda0);
        }

        vecf64  lambdas_filtered;
        for (float_64_bit const  lambda : lambdas)
            lambdas_filtered.push_back(cast_float_value<float_64_bit>(lambda));

        for (float_64_bit const  lambda : lambdas_filtered)
        {
            vecf64  shift;
            if (shift_ptr != nullptr)
            {
                shift = *shift_ptr;
                add_scaled(shift, lambda, g);
            }
            else
                shift = scale_cp(g, lambda);

            if (!clip_shift_by_constraints(space.constraints, g, shift))
            {
                // Failing linear constraints does not guarantee failure for a non-linear function.
                // => We use the (partially clipped) shift anyway.
                int iii = 0;
            }

            if (!isfinite(shift))
                continue;

            vecf64 const  point{ add_cp(origin, transform_shift(shift, space_index)) };
            if (!isfinite(point))
                continue;

            vector_overlay const  point_overlay{ make_vector_overlay(point, types_of_variables) };
            if (!is_finite(point_overlay, types_of_variables))
                continue;
            if (tested_origins.contains(point_overlay) || used_origins.contains(point_overlay))
                continue;

            resulting_shifts.push_back(shift);
            used_origins.insert(point_overlay);
        }
    }
}


bool  chain_minimization_analysis::apply_best_gradient_step()
{
    std::size_t  i_best{ descent_props.results.size() };
    for (std::size_t  i = 0UL; i < descent_props.results.size(); ++i)
    {
        {
            ASSUMPTION(descent_props.results.at(i).values.size() == path.size());
            bool all_finite{ true };
            for (auto const  value : descent_props.results.at(i).values)
                if (!std::isfinite(value))
                {
                    all_finite = false;
                    break;
                }
            if (!all_finite)
                continue;
        }

        if (i_best == descent_props.results.size())
        {
            i_best = i;
            continue;
        }

        float_64_bit const  i_best_value{ descent_props.results.at(i_best).values.back() };
        float_64_bit const  i_value{ descent_props.results.at(i).values.back() };

        auto const&  moves_origin_closer_to_zero = [this, i, i_best]() {
            vecf64 const  point_best{ add_cp(origin, transform_shift(descent_props.shifts.at(i_best), local_spaces.size() - 1UL)) };
            vecf64 const  point_i{ add_cp(origin, transform_shift(descent_props.shifts.at(i), local_spaces.size() - 1UL)) };
            float_64_bit const  len_best{ length(point_best) };
            float_64_bit const  len_i{ length(point_i) };
            return len_i < len_best;
        };

        bool  is_improving{ false };
        switch (path.back().predicate)
        {
            case BP_EQUAL:
                if (std::fabs(i_value) < std::fabs(i_best_value))
                    is_improving = true;
                else if (std::fabs(i_value) == std::fabs(i_best_value) && moves_origin_closer_to_zero())
                    is_improving = true;
                break;
            case BP_UNEQUAL:
                if (std::fabs(i_value) > std::fabs(i_best_value))
                    is_improving = true;
                else if (std::fabs(i_value) == std::fabs(i_best_value) && moves_origin_closer_to_zero())
                    is_improving = true;
                break;
            case BP_LESS:
            case BP_LESS_EQUAL:
                if (i_value < i_best_value)
                    is_improving = true;
                else if (i_value == i_best_value && moves_origin_closer_to_zero())
                    is_improving = true;
                break;
            case BP_GREATER:
            case BP_GREATER_EQUAL:
                if (i_value > i_best_value)
                    is_improving = true;
                else if (i_value == i_best_value && moves_origin_closer_to_zero())
                    is_improving = true;
                break;
            default: { UNREACHABLE(); } break;
        }

        if (is_improving)
            i_best = i;
    }

    if (i_best == descent_props.results.size())
        return false;

    gradient_descent_props::execution_result const&  best_result{ descent_props.results.at(i_best) };
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
            vecf64 const  error_vec{ add_scaled_cp(diff, -dot_product(ray_dir, diff) * dd_inv, ray_dir) };
            float_64_bit const  error{ dot_product(error_vec, error_vec) };
            float_64_bit const  sample{ dot_product(ray_dir, sub_cp(point, ray_start)) * dd_inv };
            if (std::isfinite(error) && !std::isnan(error) && std::isfinite(sample) && !std::isnan(sample))
                samples.push_back({ error, sample });
        }
    }
    std::sort(samples.begin(), samples.end());
    return samples.empty() ? 0.0 : sign * samples.front().second;
}


void  chain_minimization_analysis::commit_execution_results(
        stdin_bits_and_types_pointer const  bits_and_types_ptr,
        vecf64 const&  values
        )
{
    bits_and_types = bits_and_types_ptr;
    bits_to_point(bits_and_types->bits, origin);

    for (std::size_t  i = 0UL; i != path.size(); ++i)
        path.at(i).value = values.at(i);

    local_spaces.clear();
    partials_props.clear();
    descent_props.clear();
    recovery_props.clear();

    insert_first_local_space();
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
