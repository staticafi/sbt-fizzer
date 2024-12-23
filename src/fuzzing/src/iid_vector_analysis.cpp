#include <fuzzing/branching_node.hpp>
#include <fuzzing/fuzzer.hpp>
#include <fuzzing/iid_vector_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <iostream>
#include <string>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>


//                                          equation
// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::equation::operator+( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] + other.values[ i ] );
    }

    return { new_values, best_value + other.best_value };
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::equation::operator-( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] - other.values[ i ] );
    }

    return { new_values, best_value - other.best_value };
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::equation::operator*( int scalar ) const
{
    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] * scalar );
    }

    return { new_values, best_value * scalar };
}

// ------------------------------------------------------------------------------------------------
int fuzzing::equation::get_vector_length() const
{
    return std::sqrt( std::inner_product( values.begin(), values.end(), values.begin(), 0 ) );
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::equation::is_any_negative() const
{
    return std::any_of( values.begin(), values.end(), []( int val ) { return val < 0; } );
}

//                                     node_direction
// ------------------------------------------------------------------------------------------------
auto fuzzing::node_direction::operator<=>( node_direction const& other ) const
{
    if ( auto const cmp = node_id.id <=> other.node_id.id; cmp != 0 )
        return cmp;

    return branching_direction <=> other.branching_direction;
}

//                                     equation_matrix
// ------------------------------------------------------------------------------------------------
fuzzing::equation_matrix fuzzing::equation_matrix::get_submatrix( std::set< node_direction > const& subset,
                                                                  bool unique ) const
{
    equation_matrix result;
    result.nodes = subset;

    for ( int i = 0; i < matrix.size(); ++i ) {
        const equation& row = matrix[ i ];

        std::vector< int > new_row_values;
        for ( const node_direction& nav : subset ) {
            auto it = std::find( nodes.begin(), nodes.end(), nav );
            if ( it != nodes.end() ) {
                new_row_values.push_back( row.values[ std::distance( nodes.begin(), it ) ] );
            }
        }

        equation new_row = { new_row_values, row.best_value };

        if ( unique ) {
            if ( std::find( result.matrix.begin(), result.matrix.end(), new_row ) == result.matrix.end() ) {
                result.matrix.push_back( new_row );
                result.all_paths.push_back( all_paths[ i ] );
            }
        } else {
            result.matrix.push_back( new_row );
            result.all_paths.push_back( all_paths[ i ] );
        }
    }

    return result;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::equation_matrix::process_node( branching_node* end_node )
{
    all_paths.push_back( end_node );

    std::vector< node_direction > path = get_path( end_node );
    bool new_node = false;
    for ( const node_direction& nav : path ) {
        auto [ it, inserted ] = nodes.insert( nav );
        new_node |= inserted;
    }

    if ( new_node ) {
        recompute_matrix();
    } else {
        add_equation( end_node );
    }
}

// ------------------------------------------------------------------------------------------------
void fuzzing::equation_matrix::add_equation( branching_node* end_node )
{
    TMPROF_BLOCK();

    std::map< node_direction, int > directions_in_path;
    for ( const node_direction& navigation : nodes ) {
        directions_in_path[ navigation ] = 0;
    }

    std::vector< node_direction > path_nodes = get_path( end_node );

    for ( const node_direction& nav : path_nodes ) {
        if ( nodes.contains( nav ) ) {
            directions_in_path[ nav ]++;
        }
    }

    std::vector< int > values_in_path;
    for ( const auto& [ direction, count ] : directions_in_path ) {
        values_in_path.push_back( count );
    }

    equation row = { values_in_path, end_node->best_coverage_value };
    matrix.push_back( row );
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::equation_matrix::contains( node_direction const& node ) const { return nodes.contains( node ); }

// ------------------------------------------------------------------------------------------------
std::pair< std::size_t, std::size_t > fuzzing::equation_matrix::get_dimensions() const
{
    return { matrix.size(), nodes.size() };
}

// ------------------------------------------------------------------------------------------------
std::map< fuzzing::equation, int > fuzzing::equation_matrix::compute_vectors()
{
    std::pair< std::size_t, std::size_t > dimensions = get_dimensions();
    std::map< equation, int > vectors_with_hits;

    for ( int i = 0; i < dimensions.first; ++i ) {
        for ( int j = 0; j < dimensions.first; ++j ) {
            if ( i == j )
                continue;

            equation difference = matrix[ i ] - matrix[ j ];

            if ( difference.is_any_negative() || difference.best_value == 0 )
                continue;

            vectors_with_hits[ difference ] = 0;
        }
    }

    for ( const auto& [ vector, hits ] : vectors_with_hits ) {
        for ( const auto& row : matrix ) {
            equation new_possible_equation = row + vector;

            if ( std::find( matrix.begin(), matrix.end(), new_possible_equation ) != matrix.end() ) {
                vectors_with_hits[ vector ]++;
            }
        }
    }

    return vectors_with_hits;
}

// ------------------------------------------------------------------------------------------------
std::vector< fuzzing::equation >& fuzzing::equation_matrix::get_matrix() { return matrix; }

// ------------------------------------------------------------------------------------------------
void fuzzing::equation_matrix::print_matrix()
{
    std::cout << "# Matrix:" << std::endl;
    for ( size_t i = 0; i < matrix.size(); ++i ) {
        for ( size_t j = 0; j < matrix[ i ].values.size(); ++j ) {
            std::cout << ( j ? " " : "" ) << matrix[ i ].values[ j ];
        }
        std::cout << " -> | " << matrix[ i ].best_value << std::endl;
    }
}

// ------------------------------------------------------------------------------------------------
std::optional< fuzzing::equation > fuzzing::equation_matrix::get_new_path_from_vector( const equation& vector )
{
    INVARIANT( vector.values.size() == nodes.size() );

    std::vector< equation > paths;
    std::pair< std::size_t, std::size_t > dimensions = get_dimensions();

    for ( const auto& row : matrix ) {
        double counts = std::abs( row.best_value ) / vector.best_value;

        if ( std::abs( counts - std::round( counts ) ) > 1e-6 ) {
            continue;
        }

        equation new_path = vector * static_cast< int >( std::round( counts ) ) + row;
        if ( new_path.is_any_negative() ) {
            continue;
        }

        paths.push_back( new_path );
    }

    if ( paths.empty() ) {
        return std::nullopt;
    }

    auto min_it = std::min_element( paths.begin(), paths.end(), []( const equation& a, const equation& b ) {
        return a.get_vector_length() < b.get_vector_length();
    } );

    return *min_it;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::equation_matrix::recompute_matrix()
{
    TMPROF_BLOCK();

    matrix.clear();

    for ( branching_node* path : all_paths ) {
        add_equation( path );
    }
}

//                                  iid_node_dependence_props
// ------------------------------------------------------------------------------------------------
std::unordered_map< location_id::id_type, float > fuzzing::iid_node_dependence_props::generate_probabilities()
{
    // print_dependencies();
    // matrix.print_matrix();

    std::set< node_direction > all_leafs = get_leaf_subsets();
    equation_matrix submatrix = matrix.get_submatrix( all_leafs, true );
    std::map< equation, int > vectors = submatrix.compute_vectors();

    equation best_vector = get_best_vector( vectors, false );

    std::optional< equation > new_path = submatrix.get_new_path_from_vector( best_vector );

    if ( !new_path.has_value() ) {
        return std::unordered_map< location_id::id_type, float >();
    }


    return std::unordered_map< location_id::id_type, float >();
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::process_node( branching_node* end_node )
{
    loop_head_to_bodies_t loop_heads_to_bodies;
    loop_endings loop_heads_ending = get_loop_heads_ending( end_node, loop_heads_to_bodies );

    compute_dependencies_by_loading( end_node, loop_heads_to_bodies, loop_heads_ending );
    compute_dependencies_by_loops( loop_heads_to_bodies, loop_heads_ending );

    matrix.process_node( end_node );
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::print_dependencies()
{
    std::cout << "# Dependencies:" << std::endl;
    std::cout << "## Dependencies by loops:" << std::endl;
    for ( const auto& [ loop, nodes ] : dependencies_by_loops ) {
        for ( const auto& body : nodes ) {
            std::cout << "- " << "`(" << body << ") → " << loop.first.id << "`" << std::endl;
        }
    }

    std::cout << "## Dependencies by loading:" << std::endl;
    for ( const auto& [ loading, nodes ] : dependencies_by_loading ) {
        for ( const auto& body : nodes ) {
            std::cout << "- " << "`(" << body << ") → " << loading.first.id << "`" << std::endl;
        }
    }
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::iid_node_dependence_props::get_best_vector( const std::map< equation, int >& vectors_with_hits,
                                                                       bool use_random )
{
    if ( vectors_with_hits.empty() ) {
        throw std::invalid_argument( "Input map is empty." );
    }

    if ( use_random ) {
        return get_random_vector( vectors_with_hits );
    }

    auto max_it = std::max_element( vectors_with_hits.begin(),
                                    vectors_with_hits.end(),
                                    []( const auto& a, const auto& b ) { return a.second < b.second; } );

    return max_it->first;
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::iid_node_dependence_props::get_random_vector( const std::map< equation, int >& vectors_with_hits )
{
    std::vector< equation > equations;
    std::vector< double > probabilities;

    int total_hits = std::accumulate( vectors_with_hits.begin(),
                                      vectors_with_hits.end(),
                                      0,
                                      []( int sum, const auto& pair ) { return sum + pair.second; } );

    if ( total_hits == 0 ) {
        throw std::invalid_argument( "Total hits is zero." );
    }

    for ( const auto& [ eq, hits ] : vectors_with_hits ) {
        equations.push_back( eq );
        probabilities.push_back( static_cast< double >( hits ) / total_hits );
    }

    std::random_device rd;
    std::mt19937 gen( rd() );
    std::discrete_distribution<> dist( probabilities.begin(), probabilities.end() );

    return equations[ dist( gen ) ];
}

// ------------------------------------------------------------------------------------------------
std::set< fuzzing::node_direction > fuzzing::iid_node_dependence_props::get_leaf_subsets()
{
    std::set< node_direction > all_leafs;
    for ( const auto& [ _, loop_bodies ] : dependencies_by_loops ) {
        all_leafs.insert( loop_bodies.begin(), loop_bodies.end() );
    }

    return all_leafs;
}

// ------------------------------------------------------------------------------------------------
std::map< location_id, bool >
fuzzing::iid_node_dependence_props::get_loop_heads_ending( branching_node* end_node,
                                                           loop_head_to_bodies_t& loop_heads_to_bodies )
{
    std::vector< fuzzer::loop_boundary_props > loops;
    fuzzing::fuzzer::detect_loops_along_path_to_node( end_node, loop_heads_to_bodies, &loops );

    std::map< location_id, bool > loop_heads_ending;

    auto is_outside_loop = [ & ]( branching_node* successor,
                                  location_id loop_head_id,
                                  const std::unordered_set< location_id >& loop_bodies ) {
        return successor != nullptr && successor->get_location_id() != loop_head_id &&
               !loop_bodies.contains( successor->get_location_id() );
    };

    for ( const auto& loop : loops ) {
        location_id loop_head_id = loop.exit->get_location_id();
        const auto& loop_bodies = loop_heads_to_bodies.at( loop_head_id );

        branching_node* loop_end_node = loop.exit;
        branching_node* left_successor = loop_end_node->successor( false ).pointer;
        branching_node* right_successor = loop_end_node->successor( true ).pointer;

        if ( is_outside_loop( left_successor, loop_head_id, loop_bodies ) ) {
            loop_heads_ending[ loop_end_node->get_location_id() ] = false;
        } else if ( is_outside_loop( right_successor, loop_head_id, loop_bodies ) ) {
            loop_heads_ending[ loop_end_node->get_location_id() ] = true;
        }
    }

    return loop_heads_ending;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::compute_dependencies_by_loading( branching_node* end_node,
                                                                          const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                                          const loop_endings& loop_heads_ending )
{
    loop_head_to_loaded_bits_t loading_loops;
    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        loading_loops[ loop_head ] = { std::numeric_limits< natural_32_bit >::max(),
                                       std::numeric_limits< natural_32_bit >::min() };
    }

    branching_node* node = end_node;
    while ( node != nullptr ) {
        for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
            if ( loop_head.id == node->get_location_id().id ) {
                natural_32_bit bits_count = node->get_num_stdin_bits();

                auto& [ min, max ] = loading_loops[ loop_head ];
                min = std::min( min, bits_count );
                max = std::max( max, bits_count );
            }
        }

        node = node->predecessor;
    }

    node = end_node;

    while ( node != nullptr ) {
        auto node_id = node->get_location_id();

        for ( const auto& [ loop_head, values ] : loading_loops ) {
            if ( !loop_heads_ending.contains( loop_head ) ) {
                continue;
            }

            bool loop_head_direction = loop_heads_ending.at( loop_head );

            const auto& [ min, max ] = values;

            auto it = std::find_if( node->sensitive_stdin_bits.begin(),
                                    node->sensitive_stdin_bits.end(),
                                    [ & ]( natural_32_bit bit_index ) {
                                        return bit_index >= min && bit_index <= max;
                                    } );

            if ( it != node->sensitive_stdin_bits.end() ) {
                for ( bool direction : { true, false } ) {
                    node_direction node_id_direction = { node_id, direction };

                    if ( matrix.contains( node_id_direction ) ) {
                        dependencies_by_loading[ { loop_head, loop_head_direction } ].insert( node_id_direction );
                    }
                }
            }
        }

        node = node->predecessor;
    }
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::compute_dependencies_by_loops( const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                                        const loop_endings& loop_heads_ending )
{
    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        if ( !loop_heads_ending.contains( loop_head ) ) {
            continue;
        }

        bool loop_head_end_direction = loop_heads_ending.at( loop_head );

        for ( const auto& body : loop_bodies ) {
            for ( bool direction : { true, false } ) {
                node_direction node_id_direction = { body, direction };

                if ( matrix.contains( node_id_direction ) )
                    dependencies_by_loops[ { loop_head, loop_head_end_direction } ].insert( node_id_direction );
            }
        }
    }
}

//                                 iid_dependencies
// ------------------------------------------------------------------------------------------------
void fuzzing::iid_dependencies::update_non_iid_nodes( sensitivity_analysis& sensitivity )
{
    for ( branching_node* node : sensitivity.get_changed_nodes() ) {
        if ( node->is_did_branching() ) {
            auto location_id = node->get_location_id();
            if ( non_iid_nodes.insert( location_id ).second ) {
                id_to_equation_map.erase( location_id );
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_dependencies::process_node_dependence( branching_node* node )
{
    TMPROF_BLOCK();

    if ( non_iid_nodes.contains( node->get_location_id() ) )
        return;

    iid_node_dependence_props& props = id_to_equation_map[ node->get_location_id() ];
    props.process_node( node );
}

// ------------------------------------------------------------------------------------------------
fuzzing::iid_node_dependence_props& fuzzing::iid_dependencies::get_props( location_id id )
{
    return id_to_equation_map.at( id );
}

// ------------------------------------------------------------------------------------------------
std::vector< location_id > fuzzing::iid_dependencies::get_iid_nodes()
{
    std::vector< location_id > result;
    for ( const auto& [ key, _ ] : id_to_equation_map ) {
        result.push_back( key );
    }

    return result;
}

//                               non member functions
// ------------------------------------------------------------------------------------------------
std::vector< fuzzing::node_direction > fuzzing::get_path( branching_node* node )
{
    std::vector< node_direction > result;

    branching_node* current = node;
    while ( current != nullptr ) {
        branching_node* predecessor = current->predecessor;
        if ( predecessor != nullptr ) {
            node_direction nav = { predecessor->get_location_id(), predecessor->successor_direction( current ) };
            result.push_back( nav );
        }
        current = predecessor;
    }

    return result;
}