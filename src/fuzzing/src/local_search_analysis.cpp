#include <fuzzing/local_search_analysis.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <map>
#include <algorithm>

namespace  fuzzing {


local_search_analysis::local_search_analysis()
    : state{ READY }
    , node{ nullptr }
    , bits_and_types{ nullptr }
    , execution_id{ 0 }
    , path{}
    , from_variables_to_input{}
    , types_of_variables{}
    , stopped_early{ false }
    , num_executions{ 0U }
    , max_executions{ 0U }
    , progress_stage{ PARTIALS }
    , origin{}
    , tested_origins{ &types_of_variables }
    , local_spaces{}
    , partials_props{}
    , descent_props{}
    , rnd_generator{}
    , statistics{}
{}


bool  local_search_analysis::is_disabled() const
{
    return false;
}


void  local_search_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready() && node_ptr != nullptr && node_ptr->has_unexplored_direction() && node_ptr->get_best_stdin() != nullptr);

    state = BUSY;
    node = node_ptr;
    bits_and_types = node->get_best_stdin();
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

    reset(rnd_generator);

    path.push_back({
            node,
            node->get_best_trace()->at(node->get_trace_index()).value,
            node->is_direction_unexplored(false) ? false : true,
            node->is_direction_unexplored(false) ? opposite_predicate(node->get_branching_predicate()) : node->get_branching_predicate(),
            node->get_xor_like_branching_function(),
            {}
            });
    for (branching_node* n = node->get_predecessor(), *s = node; n != nullptr; s = n, n = n->get_predecessor())
        path.push_back({
                n,
                node->get_best_trace()->at(n->get_trace_index()).value,
                n->successor_direction(s),
                n->successor_direction(s) ? n->get_branching_predicate() : opposite_predicate(n->get_branching_predicate()),
                n->get_xor_like_branching_function(),
                {}
                });
    std::reverse(path.begin(), path.end());

    std::map<natural_32_bit, std::pair<type_of_input_bits, std::unordered_set<natural_8_bit> > >  start_bits_to_bit_indices;
    for (natural_32_bit  i = 0U, i_end = (natural_32_bit)path.size(); i != i_end; ++i)
        for (stdin_bit_index  idx : path.at(i).node_ptr->get_sensitive_stdin_bits())
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
        for (stdin_bit_index  idx : info.node_ptr->get_sensitive_stdin_bits())
        {
            natural_32_bit const  type_index = bits_and_types->type_index(idx);
            natural_32_bit const  start_bit_idx = bits_and_types->type_start_bit_index(type_index);
            info.variable_indices.insert(start_bits_to_variable_indices.at(start_bit_idx));
        }
    }

    {
        natural_32_bit const  nvars{ (natural_32_bit)types_of_variables.size() };
        natural_32_bit const  nspaces{ (natural_32_bit)path.size() };
        natural_32_bit const  npartial_shifts{ 2U * nvars };
        natural_32_bit const  nstep_shifts{ 2U + 4U };

        max_executions = 10U * (nspaces * npartial_shifts + nstep_shifts);
    }

    bits_to_point(bits_and_types->bits, origin);
    tested_origins.insert(make_vector_overlay(origin, types_of_variables));

    insert_first_local_space();

    ++statistics.start_calls;
}


void  local_search_analysis::stop()
{
    if (!is_busy())
        return;

    if (num_executions < max_num_executions())
    {
        stopped_early = true;

        ++statistics.stop_calls_early;
    }
    else
        ++statistics.stop_calls_regular;

    node->set_local_search_performed(execution_id);

    state = READY;
}


void  local_search_analysis::stop_with_failure()
{
    if (!is_busy())
        return;

    node->set_local_search_performed(execution_id);

    stopped_early = true;

    state = READY;

    ++statistics.stop_calls_failed;
}


bool  local_search_analysis::generate_next_input(vecb&  bits_ref)
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
            if (!compute_descent_shifts(descent_props.shifts, local_spaces.size() - 1UL, path.back().value))
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
        else { UNREACHABLE(); }
    }

    vecf64 const  shifted_origin{ add_cp(origin, local_spaces.front().sample_shift) };
    ASSUMPTION(isfinite(shifted_origin));
    vector_overlay const  shifted_origin_overlay{ point_to_bits(shifted_origin, bits_ref) };
    tested_origins.insert(shifted_origin_overlay);

    ++statistics.generated_inputs;

    return true;
}


void  local_search_analysis::process_execution_results(
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
        if (trace_ptr->at(last_index).id != path.at(last_index).node_ptr->get_location_id())
        {
            stop_with_failure();
            return;
        }
        local_spaces.at(last_index).sample_value = cast_float_value<float_64_bit>(trace_ptr->at(last_index).value);
        if (last_index < local_spaces.size() - 1UL && trace_ptr->at(last_index).direction != path.at(last_index).direction)
            break;
    }

    if (last_index != local_spaces.size())
    {
        stop_with_failure();
        return;
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
                    compute_descent_shifts(descent_props.shifts, local_spaces.size() - 1UL, path.back().value);
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
        default: { UNREACHABLE(); } break;
    }
}


void  local_search_analysis::compute_shifts_of_next_partial()
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


void  local_search_analysis::compute_partial_derivative()
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


void  local_search_analysis::transform_shift(std::size_t const  src_space_index) const
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


vecf64 const&  local_search_analysis::transform_shift(vecf64 const&  shift, std::size_t const  src_space_index) const
{
    ASSUMPTION(src_space_index < local_spaces.size());
    local_spaces.at(src_space_index).sample_shift = shift;
    transform_shift(src_space_index);
    return local_spaces.front().sample_shift;
}


void  local_search_analysis::transform_shift_back(std::size_t const  dst_space_index) const
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


vecf64 const&  local_search_analysis::transform_shift_back(vecf64 const&  shift, std::size_t  dst_space_index) const
{
    ASSUMPTION(dst_space_index < local_spaces.size());
    local_spaces.front().sample_shift = shift;
    transform_shift_back(dst_space_index);
    return local_spaces.at(dst_space_index).sample_shift;
}


void  local_search_analysis::insert_first_local_space()
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


void  local_search_analysis::insert_next_local_space()
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


bool  local_search_analysis::are_constraints_satisfied(std::vector<spatial_constraint> const& constraints, vecf64 const&  shift) const
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


bool  local_search_analysis::clip_shift_by_constraints(
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


bool  local_search_analysis::compute_descent_shifts(
        std::vector<vecf64>&  resulting_shifts,
        std::size_t const  space_index,
        float_64_bit const  value
        )
{
    local_space_of_branching const&  space{ local_spaces.at(space_index) };
    comparator_type const  predicate{ path.at(space_index).predicate };

    vecf64 const  g{ space.gradient };
    float_64_bit const  gg_inv{ 1.0 / dot_product(g, g)};
    float_64_bit const  lambda0{ -value * gg_inv };
    if (!std::isfinite(gg_inv) || std::isnan(gg_inv) || !std::isfinite(lambda0) || std::isnan(lambda0))
        return false;
    for (auto const coord : g)
    {
        float_64_bit const  x{ coord * lambda0 };
        if (!std::isfinite(x) || std::isnan(x))
            return false;
    }

    origin_set  used_origins{ &types_of_variables };

    vecf64  lambdas;
    {
        vecf64 const  ray_dir{ transform_shift(g, space_index) };
        vecf64  ray_start{ add_scaled_cp(origin, lambda0, ray_dir) };

        float_64_bit  param;
        {
            float_64_bit constexpr  coef{ 0.01 };
            float_64_bit const  interpolant{ (1.0 - coef) * max_abs(ray_start) + coef * std::fabs(path.at(space_index).value) };
            param = small_delta_around(cast_float_value<float_64_bit>(interpolant));
            param /= length(ray_dir);
        }

        origin_set  ignored_points{ tested_origins };
        ignored_points.insert(make_vector_overlay(ray_start, types_of_variables));

        switch (predicate)
        {
            case BP_EQUAL:
                //ASSUMPTION(value != 0.0);// && lambda0 != 0.0);
                lambdas.push_back(lambda0);
                break;
            case BP_UNEQUAL:
                //ASSUMPTION(value == 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_LESS:
                //ASSUMPTION(value >= 0.0);// && lambda0 <= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_LESS_EQUAL:
                //ASSUMPTION(value > 0.0);// && lambda0 < 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BP_GREATER:
                //ASSUMPTION(value <= 0.0);// && lambda0 >= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            case BP_GREATER_EQUAL:
                //ASSUMPTION(value < 0.0);// && lambda0 > 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            default: { UNREACHABLE(); } break;
        }

        static vecf64 const multipliers {
            100.0,
            10.0,
            0.1,
            0.01,
            };
        for (float_64_bit const  m : multipliers)
            lambdas.push_back(m * lambda0);
    }

    vecf64  lambdas_filtered;
    for (float_64_bit const  lambda : lambdas)
        lambdas_filtered.push_back(cast_float_value<float_64_bit>(lambda));

    for (float_64_bit const  lambda : lambdas_filtered)
    {
        vecf64  shift{ scale_cp(g, lambda) };

        clip_shift_by_constraints(space.constraints, g, shift);

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

    return !resulting_shifts.empty();
}


bool  local_search_analysis::apply_best_gradient_step()
{
    float_64_bit  best_value{ path.back().value };
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

        float_64_bit const  i_value{ descent_props.results.at(i).values.back() };

        bool  is_improving{ false };
        switch (path.back().predicate)
        {
            case BP_EQUAL:
                if (std::fabs(i_value) < std::fabs(best_value))
                    is_improving = true;
                break;
            case BP_UNEQUAL:
                if (std::fabs(i_value) > std::fabs(best_value))
                    is_improving = true;
                break;
            case BP_LESS:
            case BP_LESS_EQUAL:
                if (i_value < best_value)
                    is_improving = true;
                break;
            case BP_GREATER:
            case BP_GREATER_EQUAL:
                if (i_value > best_value)
                    is_improving = true;
                break;
            default: { UNREACHABLE(); } break;
        }

        if (is_improving)
        {
            i_best = i;
            best_value = i_value;
        }
    }

    if (i_best == descent_props.results.size())
        return false;

    gradient_descent_props::execution_result const&  best_result{ descent_props.results.at(i_best) };
    commit_execution_results(best_result.bits_and_types_ptr, best_result.values);

    return true;
}


float_64_bit  local_search_analysis::compute_best_shift_along_ray(
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


void  local_search_analysis::commit_execution_results(
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

    insert_first_local_space();
}


void  local_search_analysis::bits_to_point(vecb const&  bits, vecf64&  point)
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


vector_overlay  local_search_analysis::point_to_bits(vecf64 const&  point, vecb&  bits)
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