#pragma once

#include <iostream>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include <fuzzing/branching_node.hpp>
#include <fuzzing/sensitivity_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>


namespace fuzzing
{
struct direction_vector {};

struct node_direction {
    location_id node_id;
    bool branching_direction;

    auto operator<=>( node_direction const& other ) const;
    bool operator==( node_direction const& other ) const;
    friend std::ostream& operator<<( std::ostream& os, const node_direction& nav )
    {
        return os << nav.node_id.id << " " << ( nav.branching_direction ? "right" : "left" );
    }
};

using loop_ending_to_bodies = std::map< std::pair< location_id, bool >, std::set< node_direction > >;
using loop_endings = std::map< location_id, bool >;
using loop_head_to_bodies_t = std::unordered_map< location_id, std::unordered_set< location_id > >;
using loop_head_to_loaded_bits_t = std::unordered_map< location_id, std::tuple< natural_32_bit, natural_32_bit > >;

struct equation {
    std::vector< float > values;
    float best_value;
};


struct equation_matrix {
    equation_matrix get_submatrix( std::set< node_direction > const& subset, bool unique ) const;
    void add_equation( branching_node* end_node );
    bool contains( node_direction const& node ) const;

private:
    std::vector< equation > matrix;
    std::set< node_direction > nodes;
};


struct iid_node_dependence_props {
    std::unordered_map< location_id::id_type, float > generate_probabilities();
    void process_node( branching_node* end_node );

    void print_dependencies();

private:
    loop_endings get_loop_heads_ending( branching_node* end_node,
                                        loop_head_to_bodies_t& loop_heads_to_bodies );
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
