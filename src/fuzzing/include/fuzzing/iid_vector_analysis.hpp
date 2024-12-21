#pragma once

#include <map>
#include <set>
#include <unordered_map>

#include <fuzzing/branching_node.hpp>
#include <fuzzing/sensitivity_analysis.hpp>

struct node_direction;
using loop_ending_to_bodies = std::map< std::pair< location_id, bool >, std::set< node_direction > >;
using loop_endings = std::map< location_id, bool >;

namespace fuzzing
{
struct node_direction {};
struct direction_vector {};


struct equation {
    std::vector< float > values;
    float best_value;
};


struct equation_matrix {
    equation_matrix get_submatrix( std::set< node_direction > const& subset, bool unique ) const;
    void add_equation( branching_node* end_node );

private:
    std::vector< equation > matrix;
};


struct iid_node_dependence_props {
    std::unordered_map< location_id::id_type, float > generate_probabilities();
    void process_node( branching_node* end_node );

private:
    loop_endings get_loop_heads_ending( branching_node* end_node ) const;
    void compute_dependencies_by_loading( branching_node* end_node, const loop_endings& loop_heads_ending );
    void compute_dependencies_by_loops( branching_node* end_node, const loop_endings& loop_heads_ending );

    equation_matrix matrix;
    loop_ending_to_bodies dependencies_by_loops;
    loop_ending_to_bodies dependencies_by_loading;
};

struct iid_dependencies {
    void update_non_iid_nodes( const sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );

private:
    std::unordered_map< location_id, iid_node_dependence_props > id_to_equation_map;
    std::set< location_id > non_iid_nodes;
};
} // namespace fuzzing
