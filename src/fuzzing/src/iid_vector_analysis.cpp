#include <fuzzing/branching_node.hpp>
#include <fuzzing/fuzzer.hpp>
#include <fuzzing/iid_vector_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <iostream>
#include <ranges>
#include <string>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

//                                       path_node_props
// ------------------------------------------------------------------------------------------------
bool fuzzing::path_node_props::get_desired_direction() const
{
    INVARIANT( computed_counts.left_count + computed_counts.right_count > 0 );

    if ( is_loop_head ) {
        return get_preferred_direction_loop_head();
    }

    if ( taken_counts.left_count < computed_counts.left_count ) {
        return false;
    }

    if ( taken_counts.right_count < computed_counts.right_count ) {
        return true;
    }

    // TODO: Should this be here?
    float total_count = computed_counts.left_count + computed_counts.right_count;
    float left_probability = static_cast< float >( computed_counts.left_count ) / total_count;
    float random_value = static_cast< float >( rand() ) / static_cast< float >( RAND_MAX );

    if ( random_value < left_probability ) {
        return false;
    } else {
        return true;
    }
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::path_node_props::can_go_direction( bool direction ) const
{
    if ( direction ) {
        return taken_counts.right_count < computed_counts.right_count;
    } else {
        return taken_counts.left_count < computed_counts.left_count;
    }
}

// ------------------------------------------------------------------------------------------------
void fuzzing::path_node_props::go_direction( bool direction )
{
    if ( direction ) {
        taken_counts.right_count++;
    } else {
        taken_counts.left_count++;
    }

    // TODO: Maybe taken count should be reset after the loop is finished, in case this loop is visited again
    // later in the code.
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::path_node_props::can_take_next_direction() const
{
    return taken_counts.left_count < computed_counts.left_count ||
           taken_counts.right_count < computed_counts.right_count;
}

// ------------------------------------------------------------------------------------------------
float_32_bit fuzzing::path_node_props::get_false_direction_probability() const
{
    INVARIANT( computed_counts.left_count + computed_counts.right_count > 0 );

    return float_32_bit( computed_counts.left_count ) /
           ( computed_counts.left_count + computed_counts.right_count );
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::path_node_props::get_preferred_direction_loop_head() const
{
    auto is_depleted = []( int computed, int taken ) { return computed == taken; };

    if ( !loop_head_direction ) {
        INVARIANT( computed_counts.left_count == 1 );
        return !is_depleted( computed_counts.right_count, taken_counts.right_count );
    } else {
        INVARIANT( computed_counts.right_count == 1 );
        return is_depleted( computed_counts.left_count, taken_counts.left_count );
    }
}

//                                         possible_path
// ------------------------------------------------------------------------------------------------
bool fuzzing::possible_path::contains( location_id::id_type id ) const { return path.contains( id ); }

// ------------------------------------------------------------------------------------------------
std::map< location_id::id_type, fuzzing::path_node_props > fuzzing::possible_path::get_path() const
{
    return path;
}

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
fuzzing::equation fuzzing::equation::operator/( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        if ( other.values[ i ] == 0 ) {
            new_values.push_back( 0 );
        } else {
            new_values.push_back( values[ i ] / other.values[ i ] );
        }
    }


    return { new_values, best_value / other.best_value };
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

// ------------------------------------------------------------------------------------------------
bool fuzzing::equation::same_values() const
{
    for ( int i = 0; i < values.size(); ++i ) {
        if ( values[ i ] != best_value ) {
            return false;
        }
    }

    return true;
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
int fuzzing::equation_matrix::get_desired_vector_direction() const
{
    auto is_positive = []( const equation& eq ) { return eq.best_value > 0; };
    auto is_negative = []( const equation& eq ) { return eq.best_value < 0; };

    if ( std::all_of( matrix.begin(), matrix.end(), is_positive ) ) {
        return -1;
    } else if ( std::all_of( matrix.begin(), matrix.end(), is_negative ) ) {
        return 1;
    } else {
        return 0;
    }
}

// ------------------------------------------------------------------------------------------------
float fuzzing::equation_matrix::get_biggest_branching_value() const
{
    float biggest_value = 0.0f;

    for ( const equation& row : matrix ) {
        if ( std::abs( row.best_value ) > biggest_value ) {
            biggest_value = std::abs( row.best_value );
        }
    }

    return biggest_value;
}

// ------------------------------------------------------------------------------------------------
std::optional< fuzzing::equation > fuzzing::equation_matrix::get_new_path_from_vector( const equation& vector )
{
    INVARIANT( vector.values.size() == nodes.size() );

    std::vector< equation > paths;
    std::pair< std::size_t, std::size_t > dimensions = get_dimensions();
    bool get_precise = true;

    auto add_if_positive = [ &paths ]( const equation& new_path ) {
        if ( !new_path.is_any_negative() ) {
            paths.push_back( new_path );
        }
    };

    for ( const auto& row : matrix ) {
        double counts = std::abs( row.best_value ) / vector.best_value;
        int rounded_counts = static_cast< int >( std::round( counts ) );

        if ( get_precise ) {
            if ( std::abs( counts - double( rounded_counts ) ) > 1e-6 ) {
                continue;
            }

            equation new_path = vector * rounded_counts + row;
            add_if_positive( new_path );
        } else {
            for ( int vector_increment = 1; vector_increment <= rounded_counts; ++vector_increment ) {
                equation new_path = ( vector * vector_increment ) + row;
                add_if_positive( new_path );
            }
        }
    }

    if ( paths.empty() ) {
        return std::nullopt;
    }

    auto min_it = std::min_element( paths.begin(), paths.end(), []( const equation& a, const equation& b ) {
        if ( std::abs( a.best_value ) == std::abs( b.best_value ) ) {
            return a.get_vector_length() < b.get_vector_length();
        }
        return std::abs( a.best_value ) < std::abs( b.best_value );
    } );

    return *min_it;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::equation_matrix::print_matrix()
{
    std::cout << "# Matrix:" << std::endl;
    for ( const node_direction& nav : nodes ) {
        std::cout << nav << " ";
    }
    std::cout << std::endl;
    for ( size_t i = 0; i < matrix.size(); ++i ) {
        for ( size_t j = 0; j < matrix[ i ].values.size(); ++j ) {
            std::cout << ( j ? " " : "" ) << matrix[ i ].values[ j ];
        }
        std::cout << " -> | " << matrix[ i ].best_value << std::endl;
    }
}


// ------------------------------------------------------------------------------------------------
BRANCHING_PREDICATE fuzzing::equation_matrix::get_branching_predicate() 
{
    ASSUMPTION( all_paths.size() > 0 );
    return all_paths[ 0 ]->branching_predicate;
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
fuzzing::possible_path fuzzing::iid_node_dependence_props::generate_probabilities()
{
    // print_dependencies();
    // matrix.print_matrix();

    std::set< node_direction > all_leafs = get_leaf_subsets();
    equation_matrix submatrix = matrix.get_submatrix( all_leafs, true );
    std::map< equation, int > vectors = submatrix.compute_vectors();
    if ( vectors.empty() ) {
        return {};
    }

    int desired_vector_direction = submatrix.get_desired_vector_direction();
    float biggest_branching_value = submatrix.get_biggest_branching_value();
    equation best_vector = get_best_vector( vectors, false, desired_vector_direction, biggest_branching_value );

    std::optional< equation > new_path = submatrix.get_new_path_from_vector( best_vector );
    if ( !new_path.has_value() ) {
        return {};
    }

    nodes_to_counts path_counts = compute_path_counts( new_path.value(), all_leafs );
    possible_path path = generate_path_from_node_counts( path_counts );

    return path;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::process_node( branching_node* end_node )
{
    loop_head_to_bodies_t loop_heads_to_bodies;
    loop_endings loop_heads_ending = get_loop_heads_ending( end_node, loop_heads_to_bodies );

    matrix.process_node( end_node );

    compute_dependencies_by_loading( end_node, loop_heads_to_bodies, loop_heads_ending );
    compute_dependencies_by_loops( loop_heads_to_bodies, loop_heads_ending );
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::print_dependencies() const
{
    std::cout << "# Dependencies:" << std::endl;
    std::cout << "## Dependencies by loops:" << std::endl;
    for ( const auto& [ loop_head, props ] : dependencies_by_loops ) {
        for ( const auto& body : props.bodies ) {
            std::cout << "- " << "`(" << body << ") → " << loop_head.id << "`" << std::endl;
        }
    }

    std::cout << "## Dependencies by loading:" << std::endl;
    for ( const auto& [ loop_head, props ] : dependencies_by_loading ) {
        for ( const auto& body : props.bodies ) {
            std::cout << "- " << "`(" << body << ") → " << loop_head.id << "`" << std::endl;
        }
    }
}

// ------------------------------------------------------------------------------------------------
int fuzzing::iid_node_dependence_props::compute_path_counts_for_nested_loops( std::map< location_id, int >& counts, int minimum_count )
{
    int previous_count = 1;

    int max_count = std::max_element( counts.begin(), counts.end(), []( const auto& a, const auto& b ) {
                        return a.second < b.second;
                    } )->second;

    int highest_count = 1;
    for ( int i = minimum_count; i <= max_count; ++i ) {

        bool is_good = true;
        for ( const auto& [ node_id, count ] : counts ) {
            if ( count % i != 0 ) {
                is_good = false;
                break;
            }
        }

        if ( is_good ) {
            highest_count = i;
            break;
        }
    }

    for ( auto& [ node_id, count ] : counts ) {
        count /= highest_count;
    }

    return highest_count;
}

// ------------------------------------------------------------------------------------------------
fuzzing::nodes_to_counts
fuzzing::iid_node_dependence_props::compute_path_counts( const equation& path,
                                                         std::set< node_direction > const& all_leafs )
{
    nodes_to_counts path_counts;

    std::vector< node_direction > leafs = std::vector< node_direction >( all_leafs.begin(), all_leafs.end() );
    std::set< location_id > loop_heads = get_loop_heads( false );

    INVARIANT( leafs.size() == path.values.size() );

    for ( int i = 0; i < leafs.size(); ++i ) {
        auto& [ left_count, right_count ] = path_counts[ leafs[ i ].node_id ];
        if ( leafs[ i ].branching_direction ) {
            right_count = path.values[ i ];
        } else {
            left_count = path.values[ i ];
        }
    }

    // First
    for ( int i = 0; i < dependencies_by_loops.size(); ++i ) {
        for ( const auto& [ loop_head, props ] : dependencies_by_loops ) {
            int loop_count = 0;
            for ( const auto& body : props.bodies ) {
                auto& [ left_count, right_count ] = path_counts[ body.node_id ];

                if ( loop_heads.contains( body.node_id ) ) {
                    loop_count = std::max( loop_count, 1 );
                } else {
                    loop_count = std::max( loop_count, left_count + right_count );
                }
            }

            if ( props.end_direction ) {
                path_counts[ loop_head ] = { loop_count, 1 };
            } else {
                path_counts[ loop_head ] = { 1, loop_count };
            }
        }
    }

    // Second
    // for ( const auto& [ loop_head, props ] : std::ranges::views::reverse( dependencies_by_loops ) ) {
    //     int non_loop_child_max_count = 1;
    //     std::map< location_id, int > counts;

    //     for ( const auto& body : props.bodies ) {
    //         auto& [ left_count, right_count ] = path_counts[ body.node_id ];

    //         if ( !loop_heads.contains( body.node_id ) ) {
    //             non_loop_child_max_count = std::max( non_loop_child_max_count, left_count + right_count );
    //         } else {
    //             counts[ body.node_id ] = std::max( left_count, right_count );
    //         }
    //     }

    //     int new_count = compute_path_counts_for_nested_loops( counts, non_loop_child_max_count );
    //     if ( props.end_direction ) {
    //         path_counts[ loop_head ] = { new_count, 1 };
    //     } else {
    //         path_counts[ loop_head ] = { 1, new_count };
    //     }

    //     for ( const auto& [ node_id, count ] : counts ) {
    //         const loop_dependencies_props& o_props = dependencies_by_loops.at( node_id );
    //         if ( o_props.end_direction ) {
    //             path_counts[ node_id ] = { count, 1 };
    //         } else {
    //             path_counts[ node_id ] = { 1, count };
    //         }
    //     }
    // }

    for ( int i = 0; i < dependencies_by_loading.size(); ++i ) {
        for ( const auto& [ loading_head, props ] : dependencies_by_loading ) {
            int loop_count = 0;
            for ( const auto& body : props.bodies ) {
                if ( !path_counts.contains( body.node_id ) ) {
                    continue;
                }

                auto& [ left_count, right_count ] = path_counts[ body.node_id ];
                loop_count = std::max( loop_count, left_count + right_count );
            }

            if ( props.end_direction ) {
                path_counts[ loading_head ] = { loop_count, 1 };
            } else {
                path_counts[ loading_head ] = { 1, loop_count };
            }
        }
    }

    // for ( auto* map : { &dependencies_by_loops, &dependencies_by_loading } ) {
    //     for ( auto& [ loop_head, props ] : *map ) {
    //         auto it = path_counts.find( loop_head );
    //         if ( it != path_counts.end() ) {
    //             props.previous_counts.push_back( it->second );
    //         }
    //     }
    // }

    return path_counts;
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation fuzzing::iid_node_dependence_props::get_best_vector( const std::map< equation, int >& vectors_with_hits,
                                                                       bool use_random,
                                                                       int desired_direction,
                                                                       float biggest_branching_value )
{
    if ( vectors_with_hits.empty() ) {
        throw std::invalid_argument( "Input map is empty." );
    }

    std::map< equation, int > filtered_vectors_with_hits;
    if ( desired_direction < 0 ) {
        std::copy_if( vectors_with_hits.begin(),
                      vectors_with_hits.end(),
                      std::inserter( filtered_vectors_with_hits, filtered_vectors_with_hits.end() ),
                      []( const auto& pair ) { return pair.first.best_value < 0; } );
    } else if ( desired_direction > 0 ) {
        std::copy_if( vectors_with_hits.begin(),
                      vectors_with_hits.end(),
                      std::inserter( filtered_vectors_with_hits, filtered_vectors_with_hits.end() ),
                      []( const auto& pair ) { return pair.first.best_value > 0; } );
    } else {
        filtered_vectors_with_hits = vectors_with_hits;
    }

    biggest_branching_value = std::abs( biggest_branching_value );
    std::erase_if( filtered_vectors_with_hits, [ biggest_branching_value ]( const auto& pair ) {
        return std::abs( pair.first.best_value ) > biggest_branching_value;
    } );

    if ( filtered_vectors_with_hits.empty() ) {
        throw std::invalid_argument( "No vectors match the desired direction." );
    }

    if ( use_random ) {
        return get_random_vector( filtered_vectors_with_hits );
    }

    auto max_it = std::max_element( filtered_vectors_with_hits.begin(),
                                    filtered_vectors_with_hits.end(),
                                    []( const auto& a, const auto& b ) {
                                        if ( a.second == b.second ) {
                                            return std::abs( a.first.best_value ) > std::abs( b.first.best_value );
                                        }
                                        return a.second < b.second;
                                    } );

    equation best_vector = max_it->first;

    // std::map< equation, int > dependent_vectors_with_hits =
    //     get_linear_dependent_vector( filtered_vectors_with_hits, best_vector );

    // if ( !dependent_vectors_with_hits.empty() ) {
    //     auto min_it = std::min_element( dependent_vectors_with_hits.begin(),
    //                                     dependent_vectors_with_hits.end(),
    //                                     []( const auto& a, const auto& b ) {
    //                                         return a.first.get_vector_length() <
    //                                         b.first.get_vector_length();
    //                                     } );

    //     best_vector = min_it->first;
    // }

    return best_vector;
}

// ------------------------------------------------------------------------------------------------
std::map< fuzzing::equation, int > fuzzing::iid_node_dependence_props::get_linear_dependent_vector(
    const std::map< equation, int >& vectors_with_hits,
    equation& best_vector )
{
    std::map< equation, int > dependent_vectors_with_hits;

    for ( const auto& [ vector, hits ] : vectors_with_hits ) {
        equation quotient = best_vector / vector;
        if ( quotient.same_values() ) {
            dependent_vectors_with_hits[ vector ] = hits;
        }
    }

    return dependent_vectors_with_hits;
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
    for ( const auto& [ _, props ] : dependencies_by_loops ) {
        for ( const auto& body : props.bodies ) {
            location_id body_id = body.node_id;
            if ( !dependencies_by_loops.contains( body_id ) ) {
                all_leafs.insert( body );
            }
        }
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
                        dependencies_by_loading[ loop_head ].bodies.insert( node_id_direction );
                        dependencies_by_loading[ loop_head ].end_direction = loop_head_direction;
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
                    dependencies_by_loops[ loop_head ].bodies.insert( node_id_direction );
                    dependencies_by_loops[ loop_head ].end_direction = loop_head_end_direction;
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
fuzzing::possible_path
fuzzing::iid_node_dependence_props::generate_path_from_node_counts( const nodes_to_counts& path_counts )
{
    std::map< location_id::id_type, path_node_props > path;
    for ( const auto& [ id, counts ] : path_counts ) {
        if ( counts.left_count == 0 && counts.right_count == 0 ) {
            continue;
        }

        bool loop_head_direction = false;
        bool is_loop_head = false;

        for ( const auto& map : { dependencies_by_loops, dependencies_by_loading } ) {
            auto it = map.find( id );
            if ( it != map.end() ) {
                is_loop_head = true;
                loop_head_direction = it->second.end_direction;
                break;
            }
        }

        path_node_props props = { counts, is_loop_head, loop_head_direction };
        path.emplace( id.id, props );
    }

    return possible_path( path );
}

// ------------------------------------------------------------------------------------------------
std::set< location_id > fuzzing::iid_node_dependence_props::get_loop_heads( bool include_loading_loops )
{
    std::set< location_id > loop_heads;
    for ( const auto& [ loop_head, _ ] : dependencies_by_loops ) {
        loop_heads.insert( loop_head );
    }

    if ( include_loading_loops ) {
        for ( const auto& [ loading_head, _ ] : dependencies_by_loading ) {
            loop_heads.insert( loading_head );
        }
    }

    return loop_heads;
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
void fuzzing::iid_dependencies::remove_node_dependence( location_id id )
{
    if ( id_to_equation_map.contains( id ) ) {
        id_to_equation_map.erase( id );
        non_iid_nodes.insert( id );
    }
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

    std::sort( result.begin(), result.end() );
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