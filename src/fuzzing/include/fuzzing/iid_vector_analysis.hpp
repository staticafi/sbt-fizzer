#pragma once

#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include <fuzzing/branching_node.hpp>
#include <fuzzing/sensitivity_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>


namespace fuzzing
{
template < typename T >
struct mean_counter {
    T mean;
    int count;

    void add( T value );
};

struct node_counts {
    int left_count;
    int right_count;

    int get_max_count() const;
};


struct path_node_props {
    path_node_props( node_counts computed_counts, bool is_loop_head, bool loop_head_end_direction )
        : computed_counts( computed_counts )
        , taken_counts( { 0, 0 } )
        , is_loop_head( is_loop_head )
        , loop_head_end_direction( loop_head_end_direction )
    {}

    bool get_desired_direction() const;
    bool can_go_direction( bool direction ) const;
    void go_direction( bool direction );
    bool can_take_next_direction() const;

    float_32_bit get_false_direction_probability() const;

    friend std::ostream& operator<<( std::ostream& os, const path_node_props& eq )
    {
        os << "L-" << eq.computed_counts.left_count << " R-" << eq.computed_counts.right_count;
        if ( eq.is_loop_head ) {
            os << " " << ( eq.loop_head_end_direction ? "R" : "L" );
        }

        return os;
    }

private:
    node_counts computed_counts;
    node_counts taken_counts;
    bool is_loop_head;
    bool loop_head_end_direction;

    bool get_preferred_direction_loop_head() const;
};


struct possible_path {
    possible_path( std::map< location_id::id_type, path_node_props > path )
        : path( std::move( path ) )
    {}

    possible_path() = default;

    bool contains( location_id::id_type id ) const;
    std::map< location_id::id_type, path_node_props > get_path() const;
    path_node_props& get_props( location_id::id_type id ) { return path.at( id ); }

    friend std::ostream& operator<<( std::ostream& os, const possible_path& eq )
    {
        for ( const auto& [ id, props ] : eq.path ) {
            os << id << ": " << props << std::endl;
        }

        return os;
    }

private:
    std::map< location_id::id_type, path_node_props > path;
};


struct equation {
    equation( std::vector< int > values, double best_value )
        : values( std::move( values ) )
        , best_value( best_value )
    {}

    std::vector< int > values;
    double best_value;

    equation operator+( const equation& other ) const;
    equation operator+( int scalar ) const;
    equation operator-( const equation& other ) const;
    equation operator*( int scalar ) const;
    equation operator*( double scalar ) const;
    equation operator/( const equation& other ) const;
    auto operator<=>( const equation& other ) const = default;
    bool operator==( const equation& other ) const = default;

    equation add_to_positive( int value ) const;
    int get_vector_size() const;
    int get_one_way_branching_count() const;
    int get_biggest_value() const;
    bool is_any_negative() const;
    bool same_values() const;
    bool is_linear_dependent( const equation& other ) const;

    friend std::ostream& operator<<( std::ostream& os, const equation& eq )
    {
        for ( int i = 0; i < eq.values.size(); ++i ) {
            os << ( i ? " " : "" ) << eq.values[ i ];
        }
        return os << " -> " << eq.best_value;
    }
};

struct node_direction {
    location_id node_id;
    bool branching_direction;

    auto operator<=>( node_direction const& other ) const;
    bool operator==( node_direction const& other ) const = default;
    friend std::ostream& operator<<( std::ostream& os, const node_direction& nav )
    {
        return os << nav.node_id.id << " " << ( nav.branching_direction ? "right" : "left" );
    }
};

struct loaded_bits_props {
    natural_32_bit min;
    natural_32_bit max;
    int loop_count;
};

struct loading_body_props {
    mean_counter< float > average_bit_size;
    natural_32_bit minimal_bit_offset = std::numeric_limits< natural_32_bit >::max();
};

struct loop_dependencies_props {
    bool end_direction;
    std::set< node_direction > bodies;
    std::vector< node_counts > previous_counts;
};

struct loading_loops_props : loop_dependencies_props {
    mean_counter< float > average_bits_per_loop;
    std::map< location_id, loading_body_props > bit_values;
};


using loop_head_to_loaded_bits_props = std::unordered_map< location_id, loaded_bits_props >;
using loop_ending_to_bodies = std::map< location_id, loop_dependencies_props >;
using loop_endings = std::map< location_id, bool >;
using loop_head_to_bodies_t = std::unordered_map< location_id, std::unordered_set< location_id > >;
using nodes_to_counts = std::map< location_id, node_counts >;

struct equation_matrix {
    equation_matrix get_submatrix( std::set< node_direction > const& subset, bool unique ) const;
    void process_node( branching_node* end_node );
    void add_equation( branching_node* end_node );
    bool contains( node_direction const& node ) const;
    std::pair< std::size_t, std::size_t > get_dimensions() const;
    std::map< equation, int > compute_vectors_with_hits();
    std::vector< equation >& get_matrix();
    std::optional< equation > get_new_leaf_counts_from_vectors( const std::vector< equation >& vector,
                                                                int generated_after_covered,
                                                                bool generate_more_data );
    int get_desired_vector_direction() const;
    float get_biggest_branching_value() const;

    void print_matrix();

    BRANCHING_PREDICATE get_branching_predicate() const;

private:
    void recompute_matrix();

    std::vector< equation > matrix;
    std::vector< branching_node* > all_paths;
    std::set< node_direction > nodes;
};

enum generation_state {
    STATE_NOT_COVERED,
    STATE_GENERATION_MORE,
    STATE_COVERED,
    STATE_GENERATION_DATA_FOR_NEXT_NODE,
    STATE_GENERATING_ARTIFICIAL_DATA
};

struct iid_node_generations_stats {
    int generation_starts = 0;
    int successful_generations = 0;
    int failed_generations = 0;

    int failed_generations_in_row = 0;

    int generated_after_covered_max = 0;
    int generated_after_covered = 0;

    int generated_for_other_node = 0;
    int generated_for_other_node_max = 0;

    int generate_artificial_data = 0;
    int generate_artificial_data_max = 0;

    generation_state state = generation_state::STATE_NOT_COVERED;

    generation_state failed_state = generation_state::STATE_GENERATING_ARTIFICIAL_DATA;
};

struct iid_node_dependence_props {
    possible_path generate_probabilities();
    void process_node( branching_node* end_node );
    iid_node_generations_stats& get_generations_stats() { return stats; }

    bool should_generate() const;
    bool needs_data_from_other_node( int max_failed_generations_in_row ) const;
    void set_as_generating_for_other_node( int minimal_max_generation_for_other_node );
    bool is_equal_branching_predicate() const;

    void print_dependencies() const;
    void print_stats( bool only_state = false ) const;


private:
    void generate_vectors_if_not_enough_data( std::vector< equation >& best_vectors, equation_matrix& submatrix );
    std::optional< std::vector< equation > > get_best_vectors( equation_matrix& submatrix, int number_of_vectors );
    possible_path return_empty_path();
    possible_path return_path( const possible_path& path );
    void compute_path_counts_for_nested_loops( nodes_to_counts& path_counts,
                                               std::map< location_id, int >& child_loop_counts,
                                               location_id loop_head_id,
                                               int minimum_count,
                                               bool use_random = false );
    int compute_loop_count_loading( nodes_to_counts& path_counts,
                                    location_id id,
                                    const std::set< location_id >& loop_heads,
                                    const loading_loops_props& props );
    void compute_path_counts_loading( nodes_to_counts& path_counts,
                                      const equation& path,
                                      const std::set< location_id >& loop_heads );
    void compute_path_counts_loops( nodes_to_counts& path_counts,
                                    const equation& path,
                                    const std::set< location_id >& loop_heads );
    nodes_to_counts compute_path_counts( const equation& path, std::set< node_direction > const& all_leafs );
    std::vector< equation > compute_best_vectors( const std::map< equation, int >& vectors_with_hits,
                                                  int number_of_vectors,
                                                  bool use_random,
                                                  int desired_direction,
                                                  float biggest_branching_value );
    std::map< equation, int > get_linear_dependent_vector( const std::map< equation, int >& vectors_with_hits,
                                                           equation& best_vector );
    std::vector< equation > get_random_vector( const std::map< equation, int >& vectors_with_hits,
                                               int number_of_vectors );
    std::set< node_direction > get_leaf_subsets();
    loop_endings get_loop_heads_ending( branching_node* end_node, loop_head_to_bodies_t& loop_heads_to_bodies );
    void compute_loading_loops( branching_node* end_node,
                                const loop_head_to_bodies_t& loop_heads_to_bodies,
                                loop_head_to_loaded_bits_props& loading_loops );
    void compute_dependencies_by_loading( branching_node* end_node,
                                          const loop_head_to_bodies_t& loop_heads_to_bodies,
                                          const loop_endings& loop_heads_ending );
    void compute_dependencies_by_loops( const loop_head_to_bodies_t& loop_heads_to_bodies,
                                        const loop_endings& loop_heads_ending );
    possible_path generate_path_from_node_counts( const nodes_to_counts& path_counts );
    std::set< location_id > get_loop_heads( bool include_loading_loops = true );

    equation_matrix matrix;
    loop_ending_to_bodies dependencies_by_loops;
    std::map< location_id, loading_loops_props > dependencies_by_loading;

    iid_node_generations_stats stats;
};

struct iid_dependencies {
    void update_non_iid_nodes( sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );
    void remove_node_dependence( location_id id );
    iid_node_dependence_props& get_props( location_id id );
    std::vector< location_id > get_iid_nodes();
    std::optional< location_id > get_next_iid_node();

private:
    std::map< location_id, iid_node_dependence_props > id_to_equation_map;
    std::set< location_id > non_iid_nodes;

    // Settings
    bool generate_more_data_after_coverage = true;
    int minimal_max_generation_after_covered = 10;
    int max_failed_generations_in_row = 3;
    int minimal_max_generation_for_other_node = 10;
};

std::vector< node_direction > get_path( branching_node* node );
} // namespace fuzzing
