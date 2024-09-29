#pragma once

#include <algorithm>
#include <cmath>
#include <iostream>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <fuzzing/branching_node.hpp>
#include <fuzzing/sensitivity_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>

struct FloatCompare {
    bool operator()( const float& a, const float& b ) const
    {
        const float epsilon = 1e-6f;
        return std::abs( a - b ) > epsilon && std::abs( a ) < std::abs( b );
    }
};

namespace fuzzing
{
struct node_direction {
    location_id node_id;
    bool direction;

    auto operator<=>( node_direction const& other ) const;
    bool operator==( node_direction const& other ) const;
    friend std::ostream& operator<<( std::ostream& os, node_direction const& nn )
    {
        os << nn.node_id.id << " " << ( nn.direction ? "right" : "left" );
        return os;
    }
};


struct iid_node_dependence_props {
    struct iid_value_props {
        int value_counts;
        float mean_depth;
    };

    std::vector< branching_node* > all_paths;
    std::set< node_direction > interesting_nodes;
    std::vector< std::vector< float > > matrix;
    std::vector< float > best_values;
    std::map< float, iid_value_props, FloatCompare > value_to_mean_depth;

    bool update_interesting_nodes( branching_node* node );
    std::vector< node_direction > get_path( branching_node* node ) const;
    void recompute_matrix();
    void add_equation( branching_node* path );
    std::vector< float > approximate_matrix() const;
    std::vector< std::pair< int, node_direction > >
    weights_to_path( std::vector< float > const& weights ) const;
    int get_node_depth( branching_node* node ) const;

    void update_value_to_mean_depth( branching_node* node );
    int get_possible_depth() const;
};

struct iid_dependencies {
    std::unordered_map< location_id, iid_node_dependence_props > id_to_equation_map;
    std::set< location_id > non_iid_nodes;

    void update_non_iid_nodes( sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );
};
} // namespace fuzzing