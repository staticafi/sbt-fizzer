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
#include <fuzzing/gradient_descent_with_convergence.hpp>
#include <fuzzing/sensitivity_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>

using loop_to_bodies_t = std::unordered_map< location_id, std::unordered_set< location_id > >;
using loading_loops_t = std::unordered_map< location_id, std::tuple< natural_32_bit, natural_32_bit > >;

struct DirectionVector {
    DirectionVector( std::vector< float > vector, float value )
        : DirectionVector( std::move( vector ), value, 0 )
    {}

    DirectionVector( std::vector< float > vector, float value, int compare_hits )
        : vector( std::move( vector ) )
        , value( value )
        , compare_hits( compare_hits )
    {}

    std::vector< float > vector;
    float value;
    int compare_hits;

    bool operator<( const DirectionVector& other ) const
    {
        // if ( value != other.value ) {
        //     return value < other.value;
        // }

        return get_vector_length() < other.get_vector_length();
    }

    bool operator==( const DirectionVector& other ) const
    {
        return std::tie( vector, value ) == std::tie( other.vector, other.value );
    }

    float get_vector_length() const
    {
        return std::sqrt( std::inner_product( vector.begin(), vector.end(), vector.begin(), 0.0f ) );
    }
};

struct TableRow {
    TableRow( std::vector< std::optional< float > > weights, GradientDescentResult result )
        : weights( std::move( weights ) )
        , result( std::move( result ) )
    {}

    bool operator==( const TableRow& other ) const
    {
        return weights == other.weights && result == other.result;
    }

    int get_non_null_count() const
    {
        return std::count_if( weights.begin(), weights.end(), []( const auto& w ) { return w.has_value(); } );
    }

    std::vector< std::optional< float > > weights;
    GradientDescentResult result;
};

struct FloatComparator {
    bool operator()( const float& a, const float& b ) const
    {
        const float epsilon = 1e-6f;
        return std::abs( a - b ) > epsilon && std::abs( a ) < std::abs( b );
    }
};


struct Mean_counter {
    float value;

    Mean_counter()
        : value( 0 )
        , count( 0 )
    {}

    void add( float new_value ) { value = value + ( new_value - value ) / ++count; }

    operator int() const { return static_cast< int >( value ); }

    friend std::ostream& operator<<( std::ostream& os, Mean_counter const& m ) { return os << m.value; }

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
        : path_decision( 0, 0 )
    {}

    friend std::ostream& operator<<( std::ostream& os, path_decision const& pd )
    {
        return os << " left: " << pd.left_current << "/" << pd.left_max << " right: " << pd.right_current
                  << "/" << pd.right_max;
    }

    bool get_next_direction();
};


struct node_direction_old {
    location_id node_id;
    bool branching_direction;

    auto operator<=>( node_direction_old const& other ) const;
    bool operator==( node_direction_old const& other ) const;
    friend std::ostream& operator<<( std::ostream& os, node_direction_old const& nn )
    {
        return os << nn.node_id.id << " " << ( nn.branching_direction ? "right" : "left" );
    }
};

struct number_statistics {
    int min;
    int max;
    Mean_counter mean;

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
    std::map< node_direction_old, number_statistics > direction_statistics;

    void process_node( branching_node* node );

private:
    void update_mean_depth( branching_node* node );
    void update_direction_counts( branching_node* node );
};

struct iid_node_dependence_props_old {
    std::vector< branching_node* > all_paths;
    std::set< node_direction_old > interesting_nodes;
    std::vector< std::vector< float > > matrix;
    std::vector< float > best_values;

    std::map< std::pair< location_id, bool >, std::set< node_direction_old > > dependencies_by_loops;
    std::map< std::pair< location_id, bool >, std::set< node_direction_old > > dependencies_by_loading;

    coverage_value_props all_cov_value_props;
    std::map< float, coverage_value_props, FloatComparator > cov_values_to_props;

    bool update_interesting_nodes( branching_node* node );
    void recompute_matrix();
    void add_equation( branching_node* path );
    std::map< location_id, path_decision > generate_path();
    std::unordered_map< location_id::id_type, float > generate_probabilities();

    void compute_dependencies_by_loading( const loop_to_bodies_t& loop_heads_to_bodies,
                                          branching_node* end_node,
                                          const std::map< location_id, bool >& loop_heads_ending );
    void compute_dependencies_by_loops( const loop_to_bodies_t& loop_heads_to_bodies,
                                        const std::map< location_id, bool >& loop_heads_ending );

private:
    std::vector< float > approximate_matrix();
    int get_possible_depth() const;
    void dependencies_generation();
    void get_best_subset( std::vector< TableRow > const& table,
                          std::vector< std::set< node_direction_old > > const& subsets,
                          std::set< node_direction_old > const& all_leafs );
    void print_dependencies();
    std::vector< node_direction_old > get_all_leafs();
    std::map< location_id::id_type, std::pair< float, float > >
    compute_counts_from_leaf_counts( std::vector< float > const& leaf_counts,
                                     std::vector< node_direction_old > all_leafs );
    std::tuple< std::vector< std::vector< float > >, std::vector< float > >
    get_unique_matrix_and_values( std::vector< std::vector< float > > const& full_matrix );
    std::set< DirectionVector > vector_computation();
    void print_subsets( std::set< node_direction_old > const& subset,
                        GradientDescentResult const& result,
                        std::vector< float > const& node_counts );
    void print_table( std::set< node_direction_old > const& all_leafs, std::vector< TableRow > const& table );

    std::vector< std::vector< float > > get_matrix( std::vector< node_direction_old > const& subset ) const;
    std::vector< std::vector< float > > get_matrix( std::set< node_direction_old > const& subset ) const;
    std::vector< std::set< node_direction_old > > get_subsets( std::set< node_direction_old > const& all_leafs );
};

struct iid_dependencies_old {
    std::unordered_map< location_id, iid_node_dependence_props_old > id_to_equation_map;
    std::set< location_id > non_iid_nodes;

    void update_non_iid_nodes( sensitivity_analysis& sensitivity );
    void process_node_dependence( branching_node* node );
};

std::vector< fuzzing::node_direction_old > get_path_old( branching_node* node );
int linear_interpolation( int x1, int y1, int x2, int y2, int x );
} // namespace fuzzing