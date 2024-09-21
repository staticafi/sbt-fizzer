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
    , full_path{}
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
    , execution_props{}
    , partials_props{}
    , descent_props{}
    , rnd_generator{}
    , statistics{}
{}


void  local_search_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    TMPROF_BLOCK();

    ASSUMPTION(
        is_ready() &&
        node_ptr->has_unexplored_direction() &&
        !node_ptr->get_sensitive_stdin_bits().empty() &&
        node_ptr->get_best_stdin() != nullptr
        );

    state = BUSY;
    node = node_ptr;
    bits_and_types = node->get_best_stdin();
    execution_id = execution_id_;
    full_path.clear();
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
    execution_props.clear();

    partials_props.clear();
    descent_props.clear();

    reset(rnd_generator);

    for (trace_index_type  i = 0U; i <= node->get_trace_index(); ++i)
        full_path.push_back({
                node->get_best_trace()->at(i).id,
                node->get_best_trace()->at(i).direction,
                std::numeric_limits<std::size_t>::max()
                });

    std::vector<branching_node*>  full_path_nodes;
    for (branching_node* n = node; n != nullptr; n = n->get_predecessor())
        full_path_nodes.push_back(n);
    std::reverse(full_path_nodes.begin(), full_path_nodes.end());

    std::map<natural_32_bit, std::pair<type_of_input_bits, std::unordered_set<natural_8_bit> > >  start_bits_to_bit_indices;
    std::vector<std::size_t>  path_node_indices;
    {
        auto const&  collect_sensitive_bits = [&start_bits_to_bit_indices, this](std::unordered_set<natural_32_bit> const&  sensitive_bits) {
            for (stdin_bit_index  idx : sensitive_bits)
            {
                natural_32_bit const  type_index = bits_and_types->type_index(idx);
                natural_32_bit const  start_bit_idx = bits_and_types->type_start_bit_index(type_index);
                type_of_input_bits  type{ bits_and_types->types.at(type_index) };
                switch (type) {
                    case type_of_input_bits::UNTYPED8: type = type_of_input_bits::SINT8; break;
                    case type_of_input_bits::UNTYPED16: type = type_of_input_bits::SINT16; break;
                    case type_of_input_bits::UNTYPED32: type = type_of_input_bits::SINT32; break;
                    case type_of_input_bits::UNTYPED64: type = type_of_input_bits::SINT64; break;
                    default: break;
                }
                auto const  it_and_state = start_bits_to_bit_indices.insert({ start_bit_idx, { type, {} } });
                it_and_state.first->second.second.insert(idx - start_bit_idx);
            }            
        };
        auto const&  intersect = [](std::unordered_set<natural_32_bit> const&  a, std::unordered_set<natural_32_bit> const&  b) {
            for (natural_32_bit idx : b)
                if (a.contains(idx))
                    return true;
            return false;
        };

        collect_sensitive_bits(node->get_sensitive_stdin_bits());
        path_node_indices.push_back(full_path_nodes.size() - 1UL);

        std::unordered_set<natural_32_bit>  sensitive_bits{ node->get_sensitive_stdin_bits() };
        for (std::size_t  i = 1UL, i_end = full_path_nodes.size(); i != i_end; ++i)
        {
            std::size_t const  node_idx{ i_end - (i + 1UL) };
            branching_node const* const  node_ptr = full_path_nodes.at(node_idx);
            if (intersect(sensitive_bits, node_ptr->get_sensitive_stdin_bits()))
            {
                collect_sensitive_bits(node_ptr->get_sensitive_stdin_bits());
                path_node_indices.push_back(node_idx);

                sensitive_bits.insert(node_ptr->get_sensitive_stdin_bits().begin(), node_ptr->get_sensitive_stdin_bits().end());
            }
        }

        std::reverse(path_node_indices.begin(), path_node_indices.end());
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

    for (std::size_t  i = 0UL; i + 1UL < path_node_indices.size(); ++i)
    {
        std::size_t const  node_idx{ path_node_indices.at(i) };

        full_path.at(node_idx).space_index = path.size();

        branching_node* const  n{ full_path_nodes.at(node_idx) }; 
        branching_node const* const  s{ full_path_nodes.at(node_idx + 1UL) }; 
        path.push_back({
                n,
                node->get_best_trace()->at(n->get_trace_index()).value,
                n->successor_direction(s),
                n->successor_direction(s) ? n->get_branching_predicate() : opposite_predicate(n->get_branching_predicate()),
                n->get_xor_like_branching_function(),
                {}
                });
    }
    full_path.back().space_index = path.size();
    path.push_back({
            node,
            node->get_best_trace()->at(node->get_trace_index()).value,
            node->is_direction_unexplored(false) ? false : true,
            node->is_direction_unexplored(false) ? opposite_predicate(node->get_branching_predicate()) : node->get_branching_predicate(),
            node->get_xor_like_branching_function(),
            {}
            });

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

        max_executions = std::min(10U * (nspaces * npartial_shifts + nstep_shifts), 10000U);
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

    for (bool done = false; !done; )
        switch (progress_stage)
        {
            case PARTIALS:
                {
                    if (!partials_props.shifts.empty())
                    {
                        execution_props.shift = partials_props.shifts.back();
                        partials_props.shifts.pop_back();

                        done = true;

                        break;
                    }

                    bool const  has_all_spaces{ local_spaces.size() ==  path.size() };
                    bool const  has_all_partials{ size(local_spaces.back().gradient) == columns(local_spaces.back().orthonormal_basis) };

                    if (has_all_spaces && has_all_partials)
                    {
                        descent_props.clear();
                        compute_descent_shifts();

                        progress_stage = DESCENT;

                        break;
                    }

                    if (has_all_partials)
                    {
                        insert_next_local_space();

                        if (columns(local_spaces.back().orthonormal_basis) == 0UL)
                        {
                            stop_with_failure();
                            return false;
                        }
                    }

                    compute_shifts_of_next_partial();
                }
                break;
            case DESCENT:
                {
                    if (descent_props.shifts.empty())
                    {
                        stop_with_failure();
                        return false;
                    }

                    execution_props.shift = descent_props.shifts.back();
                    descent_props.shifts.pop_back();

                    done = true;
                }
                break;
            default: UNREACHABLE(); break;
        }

    execution_props.shift_in_world_space = transform_shift(execution_props.shift, local_spaces.size() - 1UL);
    execution_props.sample = add_cp(origin, execution_props.shift_in_world_space);
    ASSUMPTION(isfinite(execution_props.sample));
    execution_props.sample_overlay = point_to_bits(execution_props.sample, bits_ref);

    tested_origins.insert(execution_props.sample_overlay);

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

    execution_props.bits_and_types_ptr = bits_and_types_ptr;
    execution_props.values.clear();

    for (std::size_t  i = 0UL, n = std::min({ full_path.size(), trace_ptr->size() }); i != n; ++i)
    {
        if (trace_ptr->at(i).id != full_path.at(i).id)
            break;

        if (full_path.at(i).space_index == execution_props.values.size())
            execution_props.values.push_back(cast_float_value<float_64_bit>(trace_ptr->at(i).value));

        if (i + 1UL < full_path.size() && trace_ptr->at(i).direction != full_path.at(i).direction)
            break;
    }

    switch (progress_stage)
    {
        case PARTIALS:
            if (execution_props.values.size() == local_spaces.size())
                compute_partial_derivative(execution_props.shift, execution_props.values.at(local_spaces.size() - 1UL));
            else if (partials_props.shifts.empty())
                local_spaces.back().gradient.push_back(0.0);
            break;
        case DESCENT:
            if (execution_props.values.size() == path.size()
                    && isfinite(execution_props.values)
                    && is_improving_value(execution_props.values.back()))
                commit_execution_results(execution_props.bits_and_types_ptr, execution_props.values);
            break;
        default: { UNREACHABLE(); } break;
    }
}


void  local_search_analysis::compute_shifts_of_next_partial()
{
    std::size_t const  space_index{ local_spaces.size() - 1UL };
    local_space_of_branching&  space{ local_spaces.at(space_index) };
    std::size_t const  partial_index{ size(space.gradient) };

    bool  has_sensitive_var{ false };
    for (natural_32_bit  var_idx : space.variable_indices.at(partial_index))
        if (path.at(space_index).variable_indices.contains(var_idx))
        {
            has_sensitive_var = true;
            break;
        }
    if (!has_sensitive_var)
    {
        space.gradient.push_back(0.0);
        return;
    }

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
        axis(shift, columns(space.orthonormal_basis), partial_index);
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

    if (partials_props.shifts.empty())
        space.gradient.push_back(0.0);
}


void  local_search_analysis::compute_partial_derivative(vecf64 const&  shift, float_64_bit const  value)
{
    local_space_of_branching&  space{ local_spaces.back() };
    ASSUMPTION(size(space.gradient) < columns(space.orthonormal_basis));
    float_64_bit const partial{ (value - path.at(local_spaces.size() - 1UL).value) / at(shift, size(space.gradient)) };
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


vecf64  local_search_analysis::transform_shift(vecf64  shift, std::size_t const  src_space_index) const
{
    ASSUMPTION(src_space_index < local_spaces.size() && isfinite(shift) && size(shift) == columns(local_spaces.at(src_space_index).orthonormal_basis));
    vecf64  temp;
    vecf64*  src_shift{ &shift };
    vecf64*  dst_shift{ &temp };
    for (std::size_t  i = src_space_index; i > 0UL; --i)
    {
        local_space_of_branching const&  space{ local_spaces.at(i) };
        reset(*dst_shift, rows(space.orthonormal_basis), 0.0);
        for (std::size_t  j = 0UL; j < columns(space.orthonormal_basis); ++j)
            add_scaled(*dst_shift, at(*src_shift, j), column(space.orthonormal_basis, j));
        std::swap(src_shift, dst_shift);
    }
    return *src_shift;
}


vecf64  local_search_analysis::transform_shift_back(vecf64  shift, std::size_t const  dst_space_index) const
{
    ASSUMPTION(dst_space_index < local_spaces.size() && isfinite(shift) && size(shift) == rows(local_spaces.front().orthonormal_basis));
    vecf64  temp;
    vecf64*  src_shift{ &shift };
    vecf64*  dst_shift{ &temp };
    for (std::size_t  i = 0UL; i < dst_space_index; ++i)
    {
        local_space_of_branching const&  space{ local_spaces.at(i + 1UL) };
        reset(*dst_shift, columns(space.orthonormal_basis), 0.0);
        for (std::size_t  j = 0UL; j < columns(space.orthonormal_basis); ++j)
            at(*dst_shift, j) = dot_product(shift, at(space.orthonormal_basis, j));
        std::swap(src_shift, dst_shift);
    }
    return *src_shift;
}


void  local_search_analysis::insert_first_local_space()
{
    ASSUMPTION(local_spaces.empty());

    local_spaces.push_back({});
    for (natural_32_bit  i = 0U, i_end = (natural_32_bit)types_of_variables.size(); i != i_end; ++i)
    {
        local_spaces.back().orthonormal_basis.push_back({});
        axis(local_spaces.back().orthonormal_basis.back(), types_of_variables.size(), i);
        local_spaces.back().variable_indices.push_back({ i });
    }
    local_spaces.back().basis_vectors_in_world_space = local_spaces.back().orthonormal_basis;
    reset(local_spaces.back().scales_of_basis_vectors_in_world_space, columns(local_spaces.back().orthonormal_basis), 1.0);
}


void  local_search_analysis::insert_next_local_space()
{
    ASSUMPTION(local_spaces.size() < path.size() && size(local_spaces.back().gradient) == columns(local_spaces.back().orthonormal_basis));

    local_spaces.push_back({});

    auto const src_space_index{ local_spaces.size() - 2UL };
    auto const dst_space_index{ local_spaces.size() - 1UL };
    local_space_of_branching const&  src_space{ local_spaces.at(src_space_index) };
    local_space_of_branching&  dst_space{ local_spaces.at(dst_space_index) };

    float_64_bit const  gg{ dot_product(src_space.gradient, src_space.gradient) };
    float_64_bit const  gg_inv{ 1.0 / gg };
    if (!std::isfinite(gg) || std::isnan(gg) || !std::isfinite(gg_inv) || std::isnan(gg_inv))
    {
        for (natural_32_bit  i = 0U; i != columns(src_space.orthonormal_basis); ++i)
        {
            dst_space.orthonormal_basis.push_back({});
            axis(dst_space.orthonormal_basis.back(), columns(src_space.orthonormal_basis), i);
            dst_space.variable_indices.push_back(src_space.variable_indices.at(i));
        }
        dst_space.basis_vectors_in_world_space = src_space.basis_vectors_in_world_space;
        dst_space.scales_of_basis_vectors_in_world_space = src_space.scales_of_basis_vectors_in_world_space;
        dst_space.constraints = src_space.constraints;
        return;
    }

    auto const& collect_variable_indices_for_last_basis_vector = [&src_space, &dst_space]() {
        std::unordered_set<natural_32_bit>  indices;
        for (std::size_t  i = 0UL; i != columns(src_space.orthonormal_basis); ++i)
            if (std::fabs(at(dst_space.orthonormal_basis.back(), i)) > 1e-6f)
                indices.insert(src_space.variable_indices.at(i).begin(), src_space.variable_indices.at(i).end());

        while (dst_space.variable_indices.size() < dst_space.orthonormal_basis.size())
            dst_space.variable_indices.push_back({});

        dst_space.variable_indices.back().assign(indices.begin(), indices.end());
        std::sort(dst_space.variable_indices.back().begin(), dst_space.variable_indices.back().end());
    };

    auto const& push_back_basis_vector_props_in_world_space = [this, src_space_index, &src_space, &dst_space] (vecf64 const&  basis_vector) -> void {
        dst_space.basis_vectors_in_world_space.push_back(this->transform_shift(basis_vector, src_space_index));
        dst_space.scales_of_basis_vectors_in_world_space.push_back( max_abs(dst_space.basis_vectors_in_world_space.back()) );
    };

    for (std::size_t  i = 0UL; i < columns(src_space.orthonormal_basis); ++i)
    {
        vecf64  w;
        axis(w, columns(src_space.orthonormal_basis), i);

        float_64_bit wg{ dot_product(w, src_space.gradient) };
        if (std::fabs(wg) < 1e-6)
        {
            dst_space.orthonormal_basis.push_back(w);
            collect_variable_indices_for_last_basis_vector();
            push_back_basis_vector_props_in_world_space(w);
        }
        else
        {
            add_scaled(w, -wg * gg_inv, src_space.gradient);
            for (vecf64 const&  v : dst_space.orthonormal_basis)
                add_scaled(w, -dot_product(w, v), v);
            float_64_bit const  ww{ dot_product(w, w) };
            if (ww > 1e-6)
            {
                scale(w, 1.0 / std::sqrt(ww));
                dst_space.orthonormal_basis.push_back(w);
                collect_variable_indices_for_last_basis_vector();
                push_back_basis_vector_props_in_world_space(w);
            }
        }
    }

    branching_info const&  src_info{ path.at(src_space_index) };
    if (src_info.predicate != BRANCHING_PREDICATE::BP_EQUAL)
    {
        float_64_bit const  g_len_inv{ 1.0 / std::sqrt(gg) };
        dst_space.orthonormal_basis.push_back(scale_cp(src_space.gradient, g_len_inv));
        collect_variable_indices_for_last_basis_vector();
        push_back_basis_vector_props_in_world_space(dst_space.orthonormal_basis.back());
        vecf64  normal;
        axis(normal, columns(dst_space.orthonormal_basis), columns(dst_space.orthonormal_basis) - 1UL);
        dst_space.constraints.push_back({
            normal,
            -src_info.value * g_len_inv,
            src_info.predicate
        });
    }

    if (dst_space.orthonormal_basis.empty())
        return;

    for (spatial_constraint const&  constraint : src_space.constraints)
    {
        vecf64  normal;
        for (vecf64 const&  u : dst_space.orthonormal_basis)
            normal.push_back(dot_product(constraint.normal, u));
        float_64_bit const  scale{
            dot_product(constraint.normal, constraint.normal) / dot_product(constraint.normal, mul(dst_space.orthonormal_basis, normal))
        };
        float_64_bit const  param{ cast_float_value<float_64_bit>(constraint.param * scale) };
        if (std::isfinite(param) && !std::isnan(param))
            dst_space.constraints.push_back({ normal, param, constraint.predicate });
    }
}


bool  local_search_analysis::are_constraints_satisfied(std::vector<spatial_constraint> const& constraints, vecf64 const&  shift) const
{
    for (spatial_constraint const&  constraint : constraints)
    {
        float_64_bit const  param{ dot_product(shift, constraint.normal) / dot_product(constraint.normal, constraint.normal) };
        switch (constraint.predicate)
        {
            case BRANCHING_PREDICATE::BP_UNEQUAL:
                if (!(param != constraint.param))
                    return false;
                break;
            case BRANCHING_PREDICATE::BP_LESS:
                if (!(param < constraint.param))
                    return false;
                break;
            case BRANCHING_PREDICATE::BP_LESS_EQUAL:
                if (!(param <= constraint.param))
                    return false;
                break;
            case BRANCHING_PREDICATE::BP_GREATER:
                if (!(param > constraint.param))
                    return false;
                break;
            case BRANCHING_PREDICATE::BP_GREATER_EQUAL:
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
                case BRANCHING_PREDICATE::BP_UNEQUAL:
                    if (!(constraint.param != param))
                    {
                        add_scaled(shift, (constraint.param + epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BRANCHING_PREDICATE::BP_LESS:
                    if (!(param < constraint.param))
                    {
                        add_scaled(shift, (constraint.param - epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BRANCHING_PREDICATE::BP_LESS_EQUAL:
                    if (!(param <= constraint.param))
                    {
                        add_scaled(shift, constraint.param - param, direction);
                        clipped = true;
                    }
                    break;
                case BRANCHING_PREDICATE::BP_GREATER:
                    if (!(param > constraint.param))
                    {
                        add_scaled(shift, (constraint.param + epsilon) - param, direction);
                        clipped = true;
                    }
                    break;
                case BRANCHING_PREDICATE::BP_GREATER_EQUAL:
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


void  local_search_analysis::compute_descent_shifts()
{
    vecf64 const&  grad{ local_spaces.back().gradient };
    compute_descent_shifts(descent_props.shifts, grad, local_spaces.size() - 1UL, path.back().value);

    std::size_t const  dim{ size(grad) };
    vecf64  g; reset(g, dim, 0.0);
    for (std::size_t i = 0UL; i != dim; ++i)
        if (at(grad, i) != 0.0)
        {
            set(g, 0.0);
            at(g, i) = at(grad, i);
            compute_descent_shifts(descent_props.shifts, g, local_spaces.size() - 1UL, path.back().value);
        }

    std::reverse(descent_props.shifts.begin(), descent_props.shifts.end());
}


void  local_search_analysis::compute_descent_shifts(
        std::vector<vecf64>&  resulting_shifts,
        vecf64 const&  g,
        std::size_t const  space_index,
        float_64_bit const  value
        )
{
    float_64_bit const  gg_inv{ 1.0 / dot_product(g, g)};
    float_64_bit const  lambda0{ -value * gg_inv };
    if (!std::isfinite(gg_inv) || std::isnan(gg_inv) || !std::isfinite(lambda0) || std::isnan(lambda0))
        return;
    for (auto const coord : g)
    {
        float_64_bit const  x{ coord * lambda0 };
        if (!std::isfinite(x) || std::isnan(x))
            return;
    }

    origin_set  used_origins{ &types_of_variables };

    vecf64  lambdas;
    {
        vecf64 const  ray_dir{ transform_shift(g, space_index) };
        vecf64  ray_start{ add_scaled_cp(origin, lambda0, ray_dir) };

        float_64_bit  param;
        {
            float_64_bit constexpr  coef{ 0.01 };
            float_64_bit const  interpolant{ (1.0 - coef) * max_abs(ray_start) + coef * std::fabs(value) };
            param = small_delta_around(cast_float_value<float_64_bit>(interpolant));
            param /= length(ray_dir);
        }

        origin_set  ignored_points{ tested_origins };
        ignored_points.insert(make_vector_overlay(ray_start, types_of_variables));

        switch (path.at(space_index).predicate)
        {
            case BRANCHING_PREDICATE::BP_EQUAL:
                //ASSUMPTION(value != 0.0);// && lambda0 != 0.0);
                lambdas.push_back(lambda0);
                break;
            case BRANCHING_PREDICATE::BP_UNEQUAL:
                //ASSUMPTION(value == 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BRANCHING_PREDICATE::BP_LESS:
                //ASSUMPTION(value >= 0.0);// && lambda0 <= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BRANCHING_PREDICATE::BP_LESS_EQUAL:
                //ASSUMPTION(value > 0.0);// && lambda0 < 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, -param, ignored_points));
                break;
            case BRANCHING_PREDICATE::BP_GREATER:
                //ASSUMPTION(value <= 0.0);// && lambda0 >= 0.0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            case BRANCHING_PREDICATE::BP_GREATER_EQUAL:
                //ASSUMPTION(value < 0.0);// && lambda0 > 0.0);
                lambdas.push_back(lambda0);
                lambdas.push_back(lambda0 + compute_best_shift_along_ray(ray_start, ray_dir, +param, ignored_points));
                break;
            default: { UNREACHABLE(); } break;
        }
    }

    vecf64  lambdas_filtered;
    for (float_64_bit const  lambda : lambdas)
        lambdas_filtered.push_back(cast_float_value<float_64_bit>(lambda));

    for (float_64_bit const  lambda : lambdas_filtered)
    {
        vecf64  shift{ scale_cp(g, lambda) };

        clip_shift_by_constraints(local_spaces.at(space_index).constraints, g, shift);

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


bool  local_search_analysis::is_improving_value(float_64_bit const  value) const
{
    switch (path.back().predicate)
    {
        case BRANCHING_PREDICATE::BP_EQUAL:
            return std::fabs(value) < std::fabs(path.back().value);
        case BRANCHING_PREDICATE::BP_UNEQUAL:
            return std::fabs(value) > std::fabs(path.back().value);
        case BRANCHING_PREDICATE::BP_LESS:
        case BRANCHING_PREDICATE::BP_LESS_EQUAL:
            return value < path.back().value;
        case BRANCHING_PREDICATE::BP_GREATER:
        case BRANCHING_PREDICATE::BP_GREATER_EQUAL:
            return value > path.back().value;
        default: { UNREACHABLE(); } return false;
    }
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

    progress_stage = PARTIALS;
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
