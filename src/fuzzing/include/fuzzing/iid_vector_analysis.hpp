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
struct node_counts {
    int left_count;
    int right_count;
};

struct equation {
    equation( std::vector< int > values, double best_value )
        : values( std::move( values ) )
        , best_value( best_value )
    {}

    std::vector< int > values;
    double best_value;

    equation operator+( const equation& other ) const;
    equation operator-( const equation& other ) const;
    equation operator*( int scalar ) const;
    auto operator<=>( const equation& other ) const = default;
    bool operator==( const equation& other ) const = default;

    int get_vector_length() const;
    bool is_any_negative() const;

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

using loop_ending_to_bodies = std::map< std::pair< location_id, bool >, std::set< node_direction > >;
using loop_endings = std::map< location_id, bool >;
using loop_head_to_bodies_t = std::unordered_map< location_id, std::unordered_set< location_id > >;
using loop_head_to_loaded_bits_t = std::unordered_map< location_id, std::tuple< natural_32_bit, natural_32_bit > >;
using nodes_to_counts = std::map< location_id::id_type, node_counts >;

struct equation_matrix {
    equation_matrix get_submatrix( std::set< node_direction > const& subset, bool unique ) const;
    void process_node( branching_node* end_node );
    void add_equation( branching_node* end_node );
    bool contains( node_direction const& node ) const;
    std::pair< std::size_t, std::size_t > get_dimensions() const;
    std::map< equation, int > compute_vectors();
    std::vector< equation >& get_matrix();
    std::optional< equation > get_new_path_from_vector( const equation& vector );

    void print_matrix();

private:
    void recompute_matrix();

    std::vector< equation > matrix;
    std::vector< branching_node* > all_paths;
    std::set< node_direction > nodes;
};


struct iid_node_dependence_props {
    std::unordered_map< location_id::id_type, float > generate_probabilities();
    void process_node( branching_node* end_node );

    void print_dependencies();

private:
    nodes_to_counts compute_path_counts( const equation& path, std::set< node_direction > const& all_leafs );
    equation get_best_vector( const std::map< equation, int >& vectors_with_hits, bool use_random );
    equation get_random_vector( const std::map< equation, int >& vectors_with_hits );
    std::set< node_direction > get_leaf_subsets();
    loop_endings get_loop_heads_ending( branching_node* end_node, loop_head_to_bodies_t& loop_heads_to_bodies );
    void compute_dependencies_by_loading( branching_node* end_node,
                                          const loop_head_to_bodies_t& loop_heads_to_bodies,
                                          const loop_endings& loop_heads_ending );
    void compute_dependencies_by_loops( const loop_head_to_bodies_t& loop_heads_to_bodies,
                                        const loop_endings& loop_heads_ending );

    equation_matrix matrix;
    loop_ending_to_bodies dependencies_by_loops;
    loop_ending_to_bodies dependencies_by_loading;
};

struct iid_dependencies {
    void update_non_iid_nodes( sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );
    iid_node_dependence_props& get_props( location_id id );
    std::vector< location_id > get_iid_nodes();

private:
    std::unordered_map< location_id, iid_node_dependence_props > id_to_equation_map;
    std::set< location_id > non_iid_nodes;
};

std::vector< node_direction > get_path( branching_node* node );
} // namespace fuzzing
