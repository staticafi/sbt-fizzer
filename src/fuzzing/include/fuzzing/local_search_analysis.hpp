#ifndef FUZZING_LOCAL_SEARCH_ANALYSIS_HPP_INCLUDED
#   define FUZZING_LOCAL_SEARCH_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <fuzzing/number_overlay.hpp>
#   include <utility/sparse_data_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <unordered_map>
#   include <unordered_set>

namespace  fuzzing {


struct  local_search_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    enum PROGRESS_STAGE
    {
        PARTIALS,
        DESCENT
    };

    struct  mapping_to_input_bits
    {
        natural_32_bit  input_start_bit_index;
        std::vector<natural_8_bit>  value_bit_indices;
    };

    struct  branching_info
    {
        branching_node*  node_ptr{ nullptr };
        float_64_bit  value{ 0.0 };
        bool  direction{ false };
        comparator_type  predicate{ BP_EQUAL };
        bool  xor_like_branching_function{ false };
        std::unordered_set<natural_32_bit>  variable_indices{};
    };

    struct  spatial_constraint
    {
        vecf64  normal{};
        float_64_bit  param{ 0.0 };
        comparator_type  predicate{ BP_EQUAL };
    };

    struct  local_space_of_branching
    {
        matf64  orthogonal_basis{};
        std::vector<spatial_constraint>  constraints{};
        std::vector<std::vector<natural_32_bit> >  variable_indices{};
        matf64  basis_vectors_in_world_space{};
        vecf64  scales_of_basis_vectors_in_world_space{};
        vecf64  gradient{};
        mutable vecf64  sample_shift{};
        mutable float_64_bit  sample_value{ 0.0 };
    };

    struct  partials_stage_props
    {
        void clear() { *this = {}; }
        std::vector<vecf64>  shifts{};
    };

    struct  gradient_descent_props
    {
        struct  execution_result
        {
            stdin_bits_and_types_pointer  bits_and_types_ptr{ nullptr };
            vecf64  values{};
        };
        void clear() { *this = {}; }
        std::vector<vecf64>  shifts{};
        std::vector<execution_result>  results{};
    };

    struct  gradient_step_result
    {
        stdin_bits_and_types_pointer  bits_and_types_ptr{ nullptr };
        vecf64  values{};
    };

    struct  origin_set
    {
        origin_set(type_vector const*  types) : types_{ types }, origins_{ 0UL, hash{ types_},  equal{ types_ } } {}
        origin_set(origin_set const&  other) : origin_set(other.types_) { origins_ = other.origins_; }
        origin_set&  operator=(origin_set const&  other) { clear(); types_ = other.types_; origins_ = other.origins_; return *this; }
        ~origin_set() { clear(); types_ = nullptr;}

        void  clear() { origins_.clear(); }
        bool  empty() const { return origins_.empty(); }
        std::size_t  size() const { return origins_.size(); }

        void  insert(vector_overlay const&  origin) { origins_.insert(origin); }
        bool  contains(vector_overlay const&  origin) const  { return origins_.contains(origin); }

    private:

        struct  hash
        {
            hash(type_vector const*  types) : types_{ types } {}
            std::size_t  operator()(vector_overlay const&  origin) const { return fuzzing::hash(origin, *types_); }
            type_vector const*  types_;
        };

        struct  equal
        {
            equal(type_vector const*  types) : types_{ types } {}
            bool  operator()(vector_overlay const&  o1, vector_overlay const&  o2) const { return fuzzing::compare(o1, o2, *types_, BP_EQUAL); }
            type_vector const*  types_;
        };

        using set_type = std::unordered_set<vector_overlay, hash, equal>;

        type_vector const*  types_;
        set_type  origins_;
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  partials{ 0 };
        std::size_t  gradient_steps{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
        std::size_t  stop_calls_failed{ 0 };
    };

    local_search_analysis();

    bool  is_disabled() const;
    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, natural_32_bit  execution_id_);
    void  stop();
    void  stop_with_failure();

    natural_32_bit  max_num_executions() const { return max_executions; }

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr, stdin_bits_and_types_pointer  bits_and_types_ptr);

    branching_node*  get_node() const { return node; }
    bool  get_stopped_early() const { return stopped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    void  compute_shifts_of_next_partial();
    void  compute_partial_derivative();
    void  transform_shift(std::size_t  src_space_index) const;
    vecf64 const&  transform_shift(vecf64 const&  shift, std::size_t  src_space_index) const;
    void  transform_shift_back(std::size_t  dst_space_index) const;
    vecf64 const&  transform_shift_back(vecf64 const&  shift, std::size_t  dst_space_index) const;
    void  insert_first_local_space();
    void  insert_next_local_space();
    bool  are_constraints_satisfied(std::vector<spatial_constraint> const&  constraints, vecf64 const&  shift) const;
    bool  clip_shift_by_constraints(
            std::vector<spatial_constraint> const&  constraints,
            vecf64 const&  gradient,
            vecf64&  shift,
            std::size_t  max_iterations = 10UL
            ) const;
    bool  compute_descent_shifts(
            std::vector<vecf64>&  resulting_shifts,
            std::size_t  space_index,
            float_64_bit  value
            );
    bool  apply_best_gradient_step();
    float_64_bit  compute_best_shift_along_ray(
            vecf64 const&  ray_start,
            vecf64  ray_dir,
            float_64_bit  param,
            origin_set const&  excluded_points
            ) const;
    void  commit_execution_results(stdin_bits_and_types_pointer  bits_and_types_ptr, vecf64 const&  values);
    void  bits_to_point(vecb const&  bits, vecf64&  point);
    vector_overlay  point_to_bits(vecf64 const&  point, vecb&  bits);

    STATE  state;
    branching_node*  node;
    stdin_bits_and_types_pointer  bits_and_types;
    natural_32_bit  execution_id;
    std::vector<branching_info>  path;
    std::vector<mapping_to_input_bits>  from_variables_to_input;
    type_vector  types_of_variables;
    bool stopped_early;
    natural_32_bit  num_executions;
    natural_32_bit  max_executions;

    PROGRESS_STAGE  progress_stage;
    vecf64  origin;
    origin_set  tested_origins;
    std::vector<local_space_of_branching>  local_spaces;
    partials_stage_props  partials_props;
    gradient_descent_props  descent_props;

    random_generator_for_natural_32_bit  rnd_generator;

    performance_statistics  statistics;
};


}

#endif