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

    operator int() const { return static_cast<int>(value); }
    
    friend std::ostream& operator<<( std::ostream& os, Mean const& m ) { return os << m.value; }

private:
    size_t count;
};

namespace fuzzing
{
struct path_decision {
    int left_current;
    int left_max;

    int right_current;
    int right_max;

    path_decision( int left, int right )
        : left_current( 0 )
        , left_max( left )
        , right_current( 0 )
        , right_max( right )
    {}

    path_decision()
        : left_current( 0 )
        , left_max( 0 )
        , right_current( 0 )
        , right_max( 0 )
    {}

    friend std::ostream& operator<<( std::ostream& os, path_decision const& pd )
    {
        return os << " left: " << pd.left_current << "/" << pd.left_max << " right: " << pd.right_current << "/" << pd.right_max;
    }

    bool get_next_direction();
};


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

struct number_statistics {
    int min;
    int max;
    Mean mean;

    number_statistics()
        : min( std::numeric_limits< int >::max() )
        , max( std::numeric_limits< int >::min() )
    {}

    friend std::ostream& operator<<( std::ostream& os, number_statistics const& ds )
    {
        return os << "min: " << ds.min << " max: " << ds.max << " mean: " << ds.mean;
    }

    void add( int value );
};

struct coverage_value_props {
    number_statistics path_depth;
    std::map< node_direction, number_statistics > direction_statistics;

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

    coverage_value_props all_cov_value_props;
    std::map< float, coverage_value_props, FloatCompare > cov_values_to_props;

    bool update_interesting_nodes( branching_node* node );
    void recompute_matrix();
    void add_equation( branching_node* path );
    std::map< location_id, path_decision > generate_path() const;

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
int linear_interpolation( int x1, int y1, int x2, int y2, int x );
} // namespace fuzzing