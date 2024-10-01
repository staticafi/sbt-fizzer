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


struct Mean {
public:
    float value;

    Mean()
        : value( 0 )
        , count( 0 )
    {}

    void add( float new_value ) { value = value + ( new_value - value ) / ++count; }

    friend std::ostream& operator<<( std::ostream& os, Mean const& m ) { return os << m.value; }

private:
    size_t count;
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
        return os << nn.node_id.id << " " << ( nn.direction ? "right" : "left" );
    }
};

struct direction_statistics {
    int min;
    int max;
    Mean mean;

    direction_statistics()
        : min( std::numeric_limits< int >::max() )
        , max( std::numeric_limits< int >::min() )
    {}

    friend std::ostream& operator<<( std::ostream& os, direction_statistics const& ds )
    {
        return os << "min: " << ds.min << " max: " << ds.max << " mean: " << ds.mean;
    }
};

struct iid_value_props {
    Mean depth;
    std::map< node_direction, direction_statistics > direction_statistics;

    void process_node( branching_node* node );

private:
    void update_mean_depth( branching_node* node );
    void update_direction_counts( branching_node* node );
};

struct iid_node_dependence_props {
    std::vector< branching_node* > all_paths;
    std::set< node_direction > interesting_nodes;
    std::vector< std::vector< float > > matrix;
    std::vector< float > best_values;
    std::map< float, iid_value_props, FloatCompare > best_value_props;

    bool update_interesting_nodes( branching_node* node );
    void recompute_matrix();
    void add_equation( branching_node* path );
    std::map< fuzzing::node_direction, int > generate_path() const;

private:
    std::vector< float > approximate_matrix() const;
    std::map< fuzzing::node_direction, int > weights_to_path( std::vector< float > const& weights ) const;

    int get_possible_depth() const;
};

struct iid_dependencies {
    std::unordered_map< location_id, iid_node_dependence_props > id_to_equation_map;
    std::set< location_id > non_iid_nodes;

    void update_non_iid_nodes( sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );
};

std::vector< fuzzing::node_direction > get_path( branching_node* node );
} // namespace fuzzing