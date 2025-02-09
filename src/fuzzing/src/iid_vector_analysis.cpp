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

namespace fuzzing
{

//                                        mean_counter
// ------------------------------------------------------------------------------------------------
template < typename T >
inline void fuzzing::mean_counter< T >::add( T value )
{
    mean = ( mean * count + value ) / ( count + 1 );
    count++;
}

//                                        node_counts
// ------------------------------------------------------------------------------------------------
int node_counts::get_max_count() const { return std::max( left_count, right_count ); }

//                                       path_node_props
// ------------------------------------------------------------------------------------------------
bool path_node_props::get_desired_direction() const
{
    INVARIANT( computed_counts.left_count + computed_counts.right_count > 0 );

    if ( is_loop_head ) {
        return get_preferred_direction_loop_head();
    }

    bool can_go_left = taken_counts.left_count < computed_counts.left_count;
    bool can_go_right = taken_counts.right_count < computed_counts.right_count;

    INVARIANT( can_go_left || can_go_right );

    if ( can_go_left && can_go_right && iid_dependencies::random_direction_in_path ) {
        return rand() % 2 == 0;
    }

    if ( can_go_left ) {
        return false;
    }

    if ( can_go_right ) {
        return true;
    }

    throw std::runtime_error( "No direction to go" );
}

// ------------------------------------------------------------------------------------------------
bool path_node_props::can_go_direction( bool direction ) const
{
    if ( direction ) {
        return taken_counts.right_count < computed_counts.right_count;
    } else {
        return taken_counts.left_count < computed_counts.left_count;
    }
}

// ------------------------------------------------------------------------------------------------
void path_node_props::go_direction( bool direction )
{
    if ( direction ) {
        taken_counts.right_count++;
    } else {
        taken_counts.left_count++;
    }

    // Reset the counts if the loop ended
    if ( is_loop_head && direction == loop_head_end_direction ) {
        taken_counts = { 0, 0 };
    }
}

// ------------------------------------------------------------------------------------------------
bool path_node_props::can_take_next_direction() const
{
    return taken_counts.left_count < computed_counts.left_count ||
           taken_counts.right_count < computed_counts.right_count;
}

// ------------------------------------------------------------------------------------------------
float_32_bit path_node_props::get_false_direction_probability() const
{
    INVARIANT( computed_counts.left_count + computed_counts.right_count > 0 );

    return float_32_bit( computed_counts.left_count ) /
           ( computed_counts.left_count + computed_counts.right_count );
}

// ------------------------------------------------------------------------------------------------
bool path_node_props::get_preferred_direction_loop_head() const
{
    auto is_depleted = []( int computed, int taken ) { return computed == taken; };

    if ( !loop_head_end_direction ) {
        // INVARIANT( computed_counts.left_count == 1 );
        return !is_depleted( computed_counts.right_count, taken_counts.right_count );
    } else {
        // INVARIANT( computed_counts.right_count == 1 );
        return is_depleted( computed_counts.left_count, taken_counts.left_count );
    }
}

//                                         possible_path
// ------------------------------------------------------------------------------------------------
bool possible_path::contains( location_id::id_type id ) const { return path.contains( id ); }

// ------------------------------------------------------------------------------------------------
std::map< location_id::id_type, path_node_props > possible_path::get_path() const { return path; }

//                                          equation
// ------------------------------------------------------------------------------------------------
equation equation::operator+( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] + other.values[ i ] );
    }

    return { new_values, best_value + other.best_value };
}

// ------------------------------------------------------------------------------------------------
equation equation::operator+( int scalar ) const
{
    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] + scalar );
    }

    return { new_values, best_value };
}

// ------------------------------------------------------------------------------------------------
equation equation::operator-( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] - other.values[ i ] );
    }

    return { new_values, best_value - other.best_value };
}

// ------------------------------------------------------------------------------------------------
equation equation::operator*( int scalar ) const
{
    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] * scalar );
    }

    return { new_values, best_value * scalar };
}

// ------------------------------------------------------------------------------------------------
equation equation::operator*( double scalar ) const
{
    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] * scalar );
    }

    return { new_values, best_value * scalar };
}

// ------------------------------------------------------------------------------------------------
equation equation::operator/( const equation& other ) const
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
equation equation::add_to_positive( int value ) const
{
    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        if ( values[ i ] != 0 ) {
            new_values.push_back( values[ i ] + value );
        } else {
            new_values.push_back( values[ i ] );
        }
    }

    return { new_values, best_value };
}

// ------------------------------------------------------------------------------------------------
equation fuzzing::equation::add_to_values( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    std::vector< int > new_values;
    for ( int i = 0; i < values.size(); ++i ) {
        new_values.push_back( values[ i ] + other.values[ i ] );
    }

    return { new_values, best_value };
}

// ------------------------------------------------------------------------------------------------
int equation::get_vector_size() const
{
    return std::accumulate( values.begin(), values.end(), 0, []( int sum, int val ) { return sum + val; } );
}

// ------------------------------------------------------------------------------------------------
int equation::get_one_way_branching_count() const
{
    return std::count_if( values.begin(), values.end(), []( int val ) { return val == 0; } );
}

// ------------------------------------------------------------------------------------------------
int equation::get_biggest_value() const { return *std::max_element( values.begin(), values.end() ); }

// ------------------------------------------------------------------------------------------------
bool equation::is_any_negative() const
{
    return std::any_of( values.begin(), values.end(), []( int val ) { return val < 0; } );
}

// ------------------------------------------------------------------------------------------------
bool equation::same_values() const
{
    for ( int i = 0; i < values.size(); ++i ) {
        if ( values[ i ] != best_value && values[ i ] != 0 ) {
            return false;
        }
    }

    return true;
}

// ------------------------------------------------------------------------------------------------
bool equation::is_linear_dependent( const equation& other ) const
{
    INVARIANT( values.size() == other.values.size() );

    double ratio = std::numeric_limits< double >::quiet_NaN();
    for ( int i = 0; i < values.size(); ++i ) {
        if ( values[ i ] == 0 && other.values[ i ] == 0 ) {
            continue;
        }

        if ( values[ i ] == 0 || other.values[ i ] == 0 ) {
            return false;
        }

        double current_ratio = double( values[ i ] ) / other.values[ i ];
        if ( std::isnan( ratio ) ) {
            ratio = current_ratio;
        } else if ( std::abs( ratio - current_ratio ) > 1e-9 ) {
            return false;
        }
    }

    if ( best_value == 0 && other.best_value == 0 ) {
        return true;
    }

    if ( best_value == 0 || other.best_value == 0 ) {
        return false;
    }

    if ( std::isnan( ratio ) ) {
        return ( best_value - other.best_value ) < 1e-7;
    }

    return std::abs( best_value / other.best_value - ratio ) < 1e-7;
}

//                                     node_direction
// ------------------------------------------------------------------------------------------------
auto node_direction::operator<=>( node_direction const& other ) const
{
    if ( auto const cmp = node_id <=> other.node_id; cmp != 0 )
        return cmp;

    return branching_direction <=> other.branching_direction;
}

//                                    dependent_loop_properties
// ------------------------------------------------------------------------------------------------
bool fuzzing::dependent_loop_properties::is_same( const std::unordered_set< location_id::id_type >& other_ids ) const
{
    return get_all_ids() == other_ids;
}

// ------------------------------------------------------------------------------------------------
std::unordered_set< location_id::id_type > fuzzing::dependent_loop_properties::get_all_ids() const
{
    std::unordered_set< location_id::id_type > all_ids;

    for ( const auto& [ head, props ] : heads ) {
        all_ids.insert( head.node_id );
    }

    for ( const auto& body : bodies ) {
        all_ids.insert( body.node_id );
    }

    return all_ids;
}

// ------------------------------------------------------------------------------------------------
std::unordered_set< location_id::id_type > fuzzing::dependent_loop_properties::get_loop_head_ids() const
{
    std::unordered_set< location_id::id_type > loop_head_ids;

    for ( const auto& [ head, props ] : heads ) {
        loop_head_ids.insert( head.node_id );
    }

    return loop_head_ids;
}

// ------------------------------------------------------------------------------------------------
std::unordered_set< location_id::id_type > fuzzing::dependent_loop_properties::get_body_ids() const
{
    std::unordered_set< location_id::id_type > body_ids;

    for ( const auto& body : bodies ) {
        body_ids.insert( body.node_id );
    }

    return body_ids;
}

// ------------------------------------------------------------------------------------------------
location_id::id_type fuzzing::dependent_loop_properties::get_smallest_loop_head_id() const
{
    location_id::id_type smallest_id = heads.begin()->first.node_id;

    for ( const auto& [ head, props ] : heads ) {
        if ( head.node_id < smallest_id ) {
            smallest_id = head.node_id;
        }
    }

    return smallest_id;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::dependent_loop_properties::set_chosen_loop_head()
{
    for ( const auto& [ head, props ] : heads ) {
        if ( !chosen_loop_head.has_value() ) {
            chosen_loop_head = head;
        }

        if ( props.count > heads.at( *chosen_loop_head ).count ) {
            chosen_loop_head = head;
        }
    }
}

//                                     dependencies_by_loops_t
// ------------------------------------------------------------------------------------------------
dependent_loop_properties&
fuzzing::dependencies_by_loops_t::get_props( const std::unordered_set< location_id::id_type >& ids,
                                             location_id::id_type loop_head_id )
{
    for ( dependent_loop_properties& loop : loops ) {
        for ( const auto& [ head, props ] : loop.heads ) {
            if ( head.node_id == loop_head_id ) {
                return loop;
            }
        }

        if ( loop.is_same( ids ) ) {
            return loop;
        }
    }

    loops.emplace_back();
    return loops.back();
}

// ------------------------------------------------------------------------------------------------
void fuzzing::dependencies_by_loops_t::merge_properties()
{
    for ( auto it = loops.begin(); it != loops.end(); it++ ) {
        std::unordered_set< location_id::id_type > head_ids = it->get_loop_head_ids();

        for ( auto body_it = it->bodies.begin(); body_it != it->bodies.end(); ) {
            if ( head_ids.contains( body_it->node_id ) ) {
                body_it = it->bodies.erase( body_it );
            } else {
                ++body_it;
            }
        }
    }

    for ( auto it_1 = loops.begin(); it_1 != loops.end(); it_1++ ) {
        for ( auto it_2 = loops.begin(); it_2 != loops.end(); ) {
            if ( it_1 == it_2 ) {
                ++it_2;
                continue;
            }

            if ( it_1->is_same( it_2->get_all_ids() ) ) {
                for ( const auto& [ head, props ] : it_2->heads ) {
                    it_1->heads[ head ].count += props.count;
                }

                it_2 = loops.erase( it_2 );

                it_1 = loops.begin();
                it_2 = loops.begin();
            } else {
                ++it_2;
            }
        }
    }

    for ( auto it = loops.begin(); it != loops.end(); it++ ) {
        std::unordered_set< location_id::id_type > head_ids = it->get_loop_head_ids();

        for ( auto body_it = it->bodies.begin(); body_it != it->bodies.end(); ) {
            if ( head_ids.contains( body_it->node_id ) ) {
                body_it = it->bodies.erase( body_it );
            } else {
                ++body_it;
            }
        }
    }

    // Not sure if deleting loops with only loop heads is a good idea
    // for ( auto it = loops.begin(); it != loops.end(); ) {
    //     if ( it->bodies.empty() ) {
    //         it = loops.erase( it );
    //     } else {
    //         ++it;
    //     }
    // }
}

// ------------------------------------------------------------------------------------------------
dependent_loop_properties& fuzzing::dependencies_by_loops_t::get_props_by_loop_head_id( location_id::id_type loop_head_id )
{
    for ( dependent_loop_properties& loop : loops ) {
        for ( const auto& [ head, props ] : loop.heads ) {
            if ( head.node_id == loop_head_id ) {
                return loop;
            }
        }
    }

    throw std::runtime_error( "Loop head not found" );
}

//                                       equation_matrix
// ------------------------------------------------------------------------------------------------
equation_matrix equation_matrix::get_submatrix( std::set< node_direction > const& subset, bool unique ) const
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
void equation_matrix::process_node( branching_node* end_node )
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
void equation_matrix::add_equation( branching_node* end_node )
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
bool equation_matrix::contains( node_direction const& node ) const { return nodes.contains( node ); }

// ------------------------------------------------------------------------------------------------
std::pair< std::size_t, std::size_t > equation_matrix::get_dimensions() const
{
    return { matrix.size(), nodes.size() };
}

// ------------------------------------------------------------------------------------------------
std::map< equation, int > equation_matrix::compute_vectors_with_hits()
{
    std::map< equation, int > vectors_with_hits;

    for ( int i = 0; i < matrix.size(); ++i ) {
        for ( int j = 0; j < matrix.size(); ++j ) {
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
std::vector< equation >& equation_matrix::get_matrix() { return matrix; }

// ------------------------------------------------------------------------------------------------
int equation_matrix::get_desired_vector_direction() const
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
float equation_matrix::get_biggest_branching_value() const
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
std::optional< equation > equation_matrix::get_new_leaf_counts_from_vectors( const std::vector< equation >& vectors,
                                                                             int generation_count_after_covered,
                                                                             bool generate_more_data )
{
    INVARIANT( !vectors.empty() );
    INVARIANT( vectors[ 0 ].values.size() == nodes.size() );

    std::vector< equation > paths;

    bool is_equal_sign = get_branching_predicate() == BRANCHING_PREDICATE::BP_EQUAL;

    for ( const auto& vector : vectors ) {
        for ( const auto& row : matrix ) {
            double counts = std::abs( row.best_value ) / std::abs( vector.best_value );
            int rounded_counts = static_cast< int >( std::round( counts ) );

            if ( std::abs( counts - double( rounded_counts ) ) > 1e-8 && !generate_more_data ) {
                continue;
            }

            equation new_path = vector * rounded_counts + row;

            if ( !is_equal_sign ) {
                new_path = new_path.add_to_values( vector );
                if ( generate_more_data ) {
                    double best_value = new_path.best_value;
                    new_path = new_path * ( 1 + iid_dependencies::percentage_to_add_to_path );
                    new_path.best_value = best_value;
                }
            }

            if ( !new_path.is_any_negative() ) {
                paths.push_back( new_path );
            }
        }
    }

    if ( paths.empty() ) {
        return std::nullopt;
    }

    auto compare_equations = []( const equation& a, const equation& b ) {
        if ( std::abs( a.best_value ) != std::abs( b.best_value ) ) {
            return std::abs( a.best_value ) < std::abs( b.best_value );
        }
        if ( a.get_vector_size() != b.get_vector_size() ) {
            return a.get_vector_size() < b.get_vector_size();
        }
        return a.get_one_way_branching_count() > b.get_one_way_branching_count();
    };

    auto min_it = std::min_element( paths.begin(), paths.end(), compare_equations );

    INVARIANT( min_it != paths.end() );
    return *min_it;
}

// ------------------------------------------------------------------------------------------------
void equation_matrix::print_matrix()
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
BRANCHING_PREDICATE equation_matrix::get_branching_predicate() const
{
    ASSUMPTION( all_paths.size() > 0 );
    return all_paths[ 0 ]->branching_predicate;
}

// ------------------------------------------------------------------------------------------------
void equation_matrix::recompute_matrix()
{
    TMPROF_BLOCK();

    matrix.clear();

    for ( branching_node* path : all_paths ) {
        add_equation( path );
    }
}

//                                  iid_node_dependence_props
// ------------------------------------------------------------------------------------------------
possible_path iid_node_dependence_props::generate_probabilities()
{
    print_dependencies();

    std::set< node_direction > all_leafs = get_leaf_subsets();
    if ( all_leafs.empty() || dependencies_by_loops.loops.empty() ) {
        return {};
    }

    TMPROF_BLOCK();
    stats.generation_starts++;
    equation_matrix submatrix = matrix.get_submatrix( all_leafs, true );

    {
        // print_stats( true );
        // print_dependencies();
        // matrix.print_matrix();
        // submatrix.print_matrix();
    }

    std::optional< std::vector< equation > > best_vectors = get_best_vectors( submatrix, 1 );

    if ( !best_vectors.has_value() ) {
        if ( stats.state != generation_state::STATE_GENERATING_ARTIFICIAL_DATA ) {
            return return_empty_path();
        }

        best_vectors = std::vector< equation >();
        generate_vectors_if_not_enough_data( *best_vectors, submatrix );
    }

    bool generate_more_data = stats.state == generation_state::STATE_GENERATION_MORE ||
                              stats.state == generation_state::STATE_GENERATION_DATA_FOR_NEXT_NODE ||
                              stats.state == generation_state::STATE_GENERATING_ARTIFICIAL_DATA;
    std::optional< equation > new_leaf_counts = submatrix.get_new_leaf_counts_from_vectors(
        *best_vectors, stats.generated_after_covered, generate_more_data );

    if ( !new_leaf_counts.has_value() ) {
        return return_empty_path();
    }

    nodes_to_counts node_counts = compute_path_counts( new_leaf_counts.value(), all_leafs );
    possible_path path = generate_path_from_node_counts( node_counts );

    // std::cout << "Generated path: " << std::endl << path << std::endl;

    return return_path( path );
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::process_node( branching_node* end_node )
{
    loop_head_to_bodies_t loop_heads_to_bodies;
    loop_endings loop_heads_ending = get_loop_heads_ending( end_node, loop_heads_to_bodies );

    matrix.process_node( end_node );

    compute_dependencies_by_loading( end_node, loop_heads_to_bodies, loop_heads_ending );
    compute_dependencies_by_loops( loop_heads_to_bodies, loop_heads_ending );
}

// ------------------------------------------------------------------------------------------------
bool iid_node_dependence_props::should_generate() const
{
    return stats.state != generation_state::STATE_COVERED;
}

// ------------------------------------------------------------------------------------------------
bool iid_node_dependence_props::too_much_failed_in_row( int max_failed_generations_in_row ) const
{
    if ( stats.state != generation_state::STATE_NOT_COVERED ) {
        return false;
    }

    if ( stats.failed_generations_in_row > max_failed_generations_in_row ) {
        return true;
    }

    return false;
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::set_as_generating_for_other_node( int minimal_max_generation_for_other_node )
{
    INVARIANT( stats.state == generation_state::STATE_COVERED );

    stats.state = generation_state::STATE_GENERATION_DATA_FOR_NEXT_NODE;
    stats.generated_for_other_node_max = minimal_max_generation_for_other_node;
    stats.generated_for_other_node = 0;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::set_as_generating_artificial_data( int minimal_max_generation_artificial_data )
{
    INVARIANT( stats.state == generation_state::STATE_NOT_COVERED );

    stats.state = generation_state::STATE_GENERATING_ARTIFICIAL_DATA;
    stats.generate_artificial_data_max = minimal_max_generation_artificial_data;
    stats.generate_artificial_data = 0;
}

// ------------------------------------------------------------------------------------------------
failed_generation_method fuzzing::iid_node_dependence_props::get_method_for_failed_generation( bool is_first )
{
    failed_generation_method new_method;

    if ( is_first ) {
        new_method = failed_generation_method::METHOD_GENERATE_ARTIFICIAL_DATA;
    } else {
        switch ( stats.last_failed_method ) {
            case failed_generation_method::METHOD_GENERATE_ARTIFICIAL_DATA:
                new_method = failed_generation_method::METHOD_GENERATE_FROM_OTHER_NODE;
                break;
            case failed_generation_method::METHOD_GENERATE_FROM_OTHER_NODE:
                new_method = failed_generation_method::METHOD_GENERATE_ARTIFICIAL_DATA;
                break;
        }
    }

    if ( new_method == failed_generation_method::METHOD_GENERATE_ARTIFICIAL_DATA ) {
        set_as_generating_artificial_data( iid_dependencies::minimal_max_generation_artificial_data );
    }

    stats.last_failed_method = new_method;
    return new_method;
}

// ------------------------------------------------------------------------------------------------
bool iid_node_dependence_props::is_equal_branching_predicate() const
{
    return matrix.get_branching_predicate() == BRANCHING_PREDICATE::BP_EQUAL;
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::print_dependencies() const
{
    std::cout << "# Dependencies:" << std::endl;
    std::cout << "## Dependencies by loops:" << std::endl;
    for ( const auto& loop : dependencies_by_loops.loops ) {
        std::cout << "Loop heads:" << std::endl;
        for ( const auto& [ head, head_props ] : loop.heads ) {
            std::cout << "- " << head << " (" << head_props.count << ")" << std::endl;
        }

        std::cout << "Loop bodies:" << std::endl;
        for ( const auto& body : loop.bodies ) {
            std::cout << "- " << body << std::endl;
        }
    }

    std::cout << "## Dependencies by loading:" << std::endl;
    for ( const auto& [ loop_head, props ] : dependencies_by_loading ) {
        std::cout << "Loop ID: " << loop_head << std::endl;
        std::cout << "Loaded bits per loop: " << props.average_bits_per_loop.mean << std::endl;
        for ( const auto& body : props.bodies ) {
            const auto& bit_props = props.bit_values.at( body.node_id );
            std::cout << "- " << "`(" << body << ") → " << loop_head << "`"
                      << ", Bits: " << bit_props.average_bit_size.mean
                      << ", offset: " << bit_props.minimal_bit_offset << std::endl;
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::print_stats( bool only_state ) const
{
    switch ( stats.state ) {
        case generation_state::STATE_NOT_COVERED:
            std::cout << "Status: STATE_NOT_COVERED" << std::endl;
            if ( !only_state ) {
                std::cout << "Failed generations/Total generations: " << stats.failed_generations << "/"
                          << stats.generation_starts << std::endl;
                std::cout << "Failed generations in row: " << stats.failed_generations_in_row << std::endl;
            }
            break;
        case generation_state::STATE_GENERATION_MORE:
            std::cout << "Status STATE_GENERATION_MORE" << std::endl;
            if ( !only_state ) {
                std::cout << "Generated after covered: " << stats.generated_after_covered << "/"
                          << stats.generated_after_covered_max << std::endl;
            }
            break;
        case generation_state::STATE_COVERED: std::cout << "STATE_COVERED" << std::endl; break;
        case generation_state::STATE_GENERATION_DATA_FOR_NEXT_NODE: {
            std::cout << "Status: STATE_GENERATION_DATA_FOR_NEXT_NODE" << std::endl;
            if ( !only_state )
                std::cout << "Generated for other node: " << stats.generated_for_other_node << "/"
                          << stats.generated_for_other_node_max << std::endl;
        } break;
        case generation_state::STATE_GENERATING_ARTIFICIAL_DATA:
            std::cout << "Status: STATE_GENERATING_ARTIFICIAL_DATA" << std::endl;
            if ( !only_state ) {
                std::cout << "Generated artificial data: " << stats.generate_artificial_data << "/"
                          << stats.generate_artificial_data_max << std::endl;
            }
            break;
    }
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::generate_vectors_if_not_enough_data( std::vector< equation >& best_vectors,
                                                                              equation_matrix& submatrix )
{
    best_vectors = std::vector< equation >();
    int desired_direction = submatrix.get_desired_vector_direction();
    std::map< equation, int > vectors = submatrix.compute_vectors_with_hits();

    auto add_to_best_vectors = [ & ]( std::vector< int > values ) {
        if ( desired_direction == 0 ) {
            best_vectors.emplace_back( values, 1 );
            best_vectors.emplace_back( values, -1 );
        } else {
            best_vectors.emplace_back( values, desired_direction );
        }
    };

    if ( vectors.empty() ) {
        std::vector< int > values( submatrix.get_dimensions().second, 1 );
        add_to_best_vectors( values );
    } else {
        for ( auto& [ vector, hits ] : vectors ) {
            equation modified_vector = vector;

            for ( auto& value : modified_vector.values ) {
                if ( value != 0 ) {
                    value = 1;
                }
            }

            add_to_best_vectors( modified_vector.values );
        }
    }
}

// ------------------------------------------------------------------------------------------------
std::optional< std::vector< equation > >
fuzzing::iid_node_dependence_props::get_best_vectors( equation_matrix& submatrix, int number_of_vectors )
{
    std::map< equation, int > vectors = submatrix.compute_vectors_with_hits();
    if ( vectors.empty() ) {
        return std::nullopt;
    }

    int desired_vector_direction = submatrix.get_desired_vector_direction();
    float biggest_branching_value = submatrix.get_biggest_branching_value();
    std::vector< equation > best_vectors =
        compute_best_vectors( vectors, number_of_vectors, false, desired_vector_direction, biggest_branching_value );

    if ( best_vectors.empty() ) {
        return std::nullopt;
    }

    return best_vectors;
}

// ------------------------------------------------------------------------------------------------
possible_path iid_node_dependence_props::return_empty_path()
{
    stats.failed_generations++;
    stats.failed_generations_in_row++;
    return possible_path();
}

// ------------------------------------------------------------------------------------------------
possible_path iid_node_dependence_props::return_path( const possible_path& path )
{
    stats.failed_generations_in_row = 0;
    stats.successful_generations++;

    if ( stats.state == generation_state::STATE_GENERATION_MORE ) {
        stats.generated_after_covered++;

        if ( stats.generated_after_covered > stats.generated_after_covered_max ) {
            stats.state = generation_state::STATE_COVERED;
        }
    }

    if ( stats.state == generation_state::STATE_GENERATION_DATA_FOR_NEXT_NODE ) {
        stats.generated_for_other_node++;

        if ( stats.generated_for_other_node > stats.generated_for_other_node_max ) {
            stats.state = generation_state::STATE_COVERED;
            stats.generated_for_other_node = 0;
        }
    }

    if ( stats.state == generation_state::STATE_GENERATING_ARTIFICIAL_DATA ) {
        stats.generate_artificial_data++;

        if ( stats.generate_artificial_data > stats.generate_artificial_data_max ) {
            stats.state = generation_state::STATE_NOT_COVERED;
            stats.generate_artificial_data = 0;
        }
    }

    return path;
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_path_counts_for_nested_loops( nodes_to_counts& path_counts,
                                                                      std::map< location_id::id_type, int >& child_loop_counts,
                                                                      location_id::id_type loop_head_id,
                                                                      int minimum_count,
                                                                      bool use_random )
{
    INVARIANT( !child_loop_counts.empty() );

    int max_child_count =
        std::max_element( child_loop_counts.begin(), child_loop_counts.end(), []( const auto& a, const auto& b ) {
            return a.second < b.second;
        } )->second;

    std::set< int > possible_counts;

    for ( int i = minimum_count; i <= max_child_count; ++i ) {
        bool is_good = true;
        for ( const auto& [ node_id, count ] : child_loop_counts ) {
            if ( count % i != 0 ) {
                is_good = false;
                break;
            }
        }

        if ( is_good ) {
            possible_counts.insert( i );
        }
    }

    if ( possible_counts.empty() ) {
        path_counts[ loop_head_id ] = { 1, 1 };
        return;
    }

    int highest_count = use_random ? *std::next( possible_counts.begin(), rand() % possible_counts.size() ) :
                                     *possible_counts.rbegin();

    for ( auto& [ node_id, count ] : child_loop_counts ) {
        dependent_loop_properties& props = dependencies_by_loops.get_props_by_loop_head_id( node_id );

        for ( auto& [ head, _ ] : props.heads ) {
            auto& [ left_count, right_count ] = path_counts[ head.node_id ];

            if ( head.branching_direction ) {
                left_count = count / highest_count;
            } else {
                right_count = count / highest_count;
            }
        }
    }


    dependent_loop_properties& props = dependencies_by_loops.get_props_by_loop_head_id( loop_head_id );
    for ( auto& [ head, _ ] : props.heads ) {
        if ( head.branching_direction ) {
            path_counts[ head.node_id ] = { highest_count, 1 };
        } else {
            path_counts[ head.node_id ] = { 1, highest_count };
        }
    }
}

// ------------------------------------------------------------------------------------------------
int fuzzing::iid_node_dependence_props::compute_loop_count_loading( nodes_to_counts& path_counts,
                                                                    location_id::id_type id,
                                                                    const std::set< location_id::id_type >& loop_heads,
                                                                    const loading_loops_props& props )
{
    float loaded_per_loop = props.average_bits_per_loop.mean;
    INVARIANT( loaded_per_loop > 0 );

    float average_bits = props.bit_values.at( id ).average_bit_size.mean;
    natural_32_bit offset = props.bit_values.at( id ).minimal_bit_offset;

    bool is_loop_head = true;
    if ( !loop_heads.contains( id ) ) {
        for ( const auto& loop : dependencies_by_loops.loops ) {
            for ( const auto& body : loop.bodies ) {
                if ( body.node_id == id ) {
                    id = ( *loop.chosen_loop_head ).node_id;
                    is_loop_head = false;
                }
            }
        }
    }

    int total_count = is_loop_head ? path_counts[ id ].get_total_count() : path_counts[ id ].get_max_count();
    float bits_needed = average_bits * total_count + offset;

    return std::ceil( bits_needed / loaded_per_loop );
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_path_counts_loading( nodes_to_counts& path_counts,
                                                             const equation& path,
                                                             const std::set< location_id::id_type >& loop_heads )
{
    for ( const auto& [ loading_head, props ] : dependencies_by_loading ) {
        int loop_count = 0;

        for ( const auto& body : props.bodies ) {
            if ( !path_counts.contains( body.node_id ) ) {
                continue;
            }

            int minimal_count = compute_loop_count_loading( path_counts, body.node_id, loop_heads, props );
            loop_count = std::max( loop_count, minimal_count );
        }

        if ( props.end_direction ) {
            path_counts[ loading_head ] = { loop_count, 1 };
        } else {
            path_counts[ loading_head ] = { 1, loop_count };
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_path_counts_loops( nodes_to_counts& path_counts,
                                                           const equation& path,
                                                           const std::set< location_id::id_type >& loop_heads )
{
    for ( const auto& props : std::ranges::views::reverse( dependencies_by_loops.loops ) ) {
        if ( props.bodies.empty() ) {
            continue;
        }

        std::map< location_id::id_type, int > child_loop_counts;
        int non_loop_child_max_count = 1;

        for ( const auto& body : props.bodies ) {
            auto& [ left_count, right_count ] = path_counts[ body.node_id ];

            if ( loop_heads.contains( body.node_id ) ) {
                child_loop_counts[ body.node_id ] = std::max( left_count, right_count );
            } else {
                non_loop_child_max_count = std::max( non_loop_child_max_count, left_count + right_count );
            }
        }

        if ( child_loop_counts.empty() ) {
            continue;
        }

        compute_path_counts_for_nested_loops( path_counts,
                                              child_loop_counts,
                                              ( *props.chosen_loop_head ).node_id,
                                              non_loop_child_max_count,
                                              iid_dependencies::random_nested_loops );
    }
}

// ------------------------------------------------------------------------------------------------
nodes_to_counts iid_node_dependence_props::compute_path_counts( const equation& path,
                                                                std::set< node_direction > const& all_leafs )
{
    nodes_to_counts path_counts;

    std::vector< node_direction > leafs = std::vector< node_direction >( all_leafs.begin(), all_leafs.end() );
    INVARIANT( leafs.size() == path.values.size() );

    std::set< location_id::id_type > loop_heads = get_loop_heads( false );

    for ( auto& loop : dependencies_by_loops.loops ) {
        loop.set_chosen_loop_head();
    }

    for ( int i = 0; i < leafs.size(); ++i ) {
        auto& [ left_count, right_count ] = path_counts[ leafs[ i ].node_id ];
        if ( leafs[ i ].branching_direction ) {
            right_count = path.values[ i ];
        } else {
            left_count = path.values[ i ];
        }
    }

    for ( const auto& loop_props : std::ranges::views::reverse( dependencies_by_loops.loops ) ) {
        if ( loop_props.bodies.empty() ) {
            continue;
        }

        int loop_count = 0;

        for ( const auto& body : loop_props.bodies ) {
            loop_count = std::max( loop_count, path_counts[ body.node_id ].get_total_count() );
        }

        for ( const auto& [ head, _ ] : loop_props.heads ) {
            int end_count = head == ( *loop_props.chosen_loop_head ) ? 1 : 0;

            if ( head.branching_direction ) {
                path_counts[ head.node_id ] = { loop_count, end_count };
            } else {
                path_counts[ head.node_id ] = { end_count, loop_count };
            }
        }
    }

    compute_path_counts_loops( path_counts, path, loop_heads );
    compute_path_counts_loading( path_counts, path, loop_heads );

    return path_counts;
}

// ------------------------------------------------------------------------------------------------
std::vector< equation > iid_node_dependence_props::compute_best_vectors( const std::map< equation, int >& vectors_with_hits,
                                                                         int number_of_vectors,
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
        return {};
    }

    if ( use_random ) {
        return get_random_vector( filtered_vectors_with_hits, number_of_vectors );
    }

    std::vector< std::pair< equation, int > > sorted_vectors( filtered_vectors_with_hits.begin(),
                                                              filtered_vectors_with_hits.end() );

    std::sort( sorted_vectors.begin(), sorted_vectors.end(), []( const auto& a, const auto& b ) {
        if ( a.second == b.second ) {
            return std::abs( a.first.best_value ) > std::abs( b.first.best_value );
        }
        return a.second > b.second;
    } );

    bool use_linear_dependency = true;
    std::vector< equation > best_vectors;
    for ( int i = 0; i < number_of_vectors && i < sorted_vectors.size(); ++i ) {
        if ( use_linear_dependency ) {
            std::map< equation, int > dependent_vectors_with_hits =
                get_linear_dependent_vector( filtered_vectors_with_hits, sorted_vectors[ i ].first );

            auto it = std::min_element( dependent_vectors_with_hits.begin(),
                                        dependent_vectors_with_hits.end(),
                                        []( const auto& a, const auto& b ) {
                                            return a.first.get_vector_size() < b.first.get_vector_size();
                                        } );
            best_vectors.push_back( it->first );
        } else {
            best_vectors.push_back( sorted_vectors[ i ].first );
        }
    }

    return best_vectors;
}

// ------------------------------------------------------------------------------------------------
std::map< equation, int >
iid_node_dependence_props::get_linear_dependent_vector( const std::map< equation, int >& vectors_with_hits,
                                                        equation& best_vector )
{
    std::map< equation, int > dependent_vectors_with_hits;

    for ( const auto& [ vector, hits ] : vectors_with_hits ) {
        if ( best_vector.is_linear_dependent( vector ) ) {
            dependent_vectors_with_hits[ vector ] = hits;
        }
    }

    INVARIANT( !dependent_vectors_with_hits.empty() );
    return dependent_vectors_with_hits;
}

// ------------------------------------------------------------------------------------------------
std::vector< equation > iid_node_dependence_props::get_random_vector( const std::map< equation, int >& vectors_with_hits,
                                                                      int number_of_vectors )
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

    std::vector< equation > selected_equations;
    for ( int i = 0; i < number_of_vectors; ++i ) {
        selected_equations.push_back( equations[ dist( gen ) ] );
    }

    return selected_equations;
}

// ------------------------------------------------------------------------------------------------
std::set< node_direction > iid_node_dependence_props::get_leaf_subsets()
{
    std::set< node_direction > all_leafs;
    auto loop_heads = get_loop_heads( false );

    for ( const auto& loop : dependencies_by_loops.loops ) {
        if ( loop.bodies.empty() ) {
            continue;
        }

        for ( const auto& body : loop.bodies ) {
            location_id::id_type body_id = body.node_id;
            if ( !loop_heads.contains( body_id ) ) {
                all_leafs.insert( body );
            }
        }

        for ( const auto& [ head, _ ] : loop.heads ) {
            all_leafs.insert( { head.node_id, !head.branching_direction } );
        }
    }

    return all_leafs;
}

// ------------------------------------------------------------------------------------------------
std::map< location_id::id_type, bool >
iid_node_dependence_props::get_loop_heads_ending( branching_node* end_node,
                                                  loop_head_to_bodies_t& loop_heads_to_bodies )
{
    std::vector< fuzzer::loop_boundary_props > loops;
    fuzzer::detect_loops_along_path_to_node( end_node, loop_heads_to_bodies, &loops );

    std::map< location_id::id_type, bool > loop_heads_ending;

    auto is_outside_loop = [ & ]( branching_node* successor,
                                  location_id loop_head_id,
                                  const std::unordered_set< location_id >& loop_bodies ) {
        if ( successor == nullptr ) {
            return false;
        }

        if ( successor->get_location_id() == loop_head_id ) {
            return false;
        }

        for ( const auto& bodies : loop_bodies ) {
            if ( bodies.id == successor->get_location_id().id ) {
                return false;
            }
        }

        return true;
    };

    for ( const auto& loop : loops ) {
        location_id loop_head_id = loop.exit->get_location_id();

        const auto& loop_bodies = loop_heads_to_bodies.at( loop_head_id );

        branching_node* loop_end_node = loop.exit;
        branching_node* left_successor = loop_end_node->successor( false ).pointer;
        branching_node* right_successor = loop_end_node->successor( true ).pointer;

        if ( is_outside_loop( left_successor, loop_head_id, loop_bodies ) ) {
            loop_heads_ending[ loop_end_node->get_location_id().id ] = false;
        } else if ( is_outside_loop( right_successor, loop_head_id, loop_bodies ) ) {
            loop_heads_ending[ loop_end_node->get_location_id().id ] = true;
        }
    }

    return loop_heads_ending;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::compute_loading_loops( branching_node* end_node,
                                                                const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                                loop_head_to_loaded_bits_props& loading_loops )
{
    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        loading_loops[ loop_head.id ] = { std::numeric_limits< natural_32_bit >::max(),
                                          std::numeric_limits< natural_32_bit >::min() };
    }

    branching_node* node = end_node;
    while ( node != nullptr ) {
        for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
            if ( loop_head.id == node->get_location_id().id ) {
                natural_32_bit bits_count = node->get_num_stdin_bits();

                auto& props = loading_loops[ loop_head.id ];
                props.min = std::min( props.min, bits_count );
                props.max = std::max( props.max, bits_count );
                props.loop_count++;
            }
        }

        node = node->predecessor;
    }

    // Remove all loops that did not load any data inside
    for ( auto it = loading_loops.begin(); it != loading_loops.end(); ) {
        if ( it->second.min == it->second.max ) {
            it = loading_loops.erase( it );
        } else {
            ++it;
        }
    }

    // Remove one loop count for branching that ends the loop
    for ( auto& [ id, props ] : loading_loops ) {
        if ( props.loop_count != 0 )
            props.loop_count--;
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_dependencies_by_loading( branching_node* end_node,
                                                                 const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                                 const loop_endings& loop_heads_ending )
{
    loop_head_to_loaded_bits_props loading_loops;
    compute_loading_loops( end_node, loop_heads_to_bodies, loading_loops );

    branching_node* node = end_node;

    struct loading_body_props_tmp {
        natural_32_bit min = std::numeric_limits< natural_32_bit >::max();
        natural_32_bit max = std::numeric_limits< natural_32_bit >::min();
        std::vector< natural_32_bit > sensitive_stdin_bit_counts;
    };

    std::map< location_id::id_type, std::map< location_id::id_type, loading_body_props_tmp > > loop_to_props;

    while ( node != nullptr ) {
        location_id::id_type node_id = node->get_location_id().id;

        for ( const auto& [ loop_head, props ] : loading_loops ) {
            if ( !loop_heads_ending.contains( loop_head ) ) {
                continue;
            }

            auto min = props.min;
            auto max = props.max;

            auto it = std::find_if( node->sensitive_stdin_bits.begin(),
                                    node->sensitive_stdin_bits.end(),
                                    [ & ]( natural_32_bit bit_index ) {
                                        return bit_index >= min && bit_index < max;
                                    } );
            if ( it == node->sensitive_stdin_bits.end() )
                continue;

            loading_body_props_tmp& loop_props = loop_to_props[ loop_head ][ node_id ];

            auto min_it = std::min_element( node->sensitive_stdin_bits.begin(), node->sensitive_stdin_bits.end() );
            if ( min_it != node->sensitive_stdin_bits.end() ) {
                loop_props.min = std::min( loop_props.min, *min_it );
            }

            auto max_it = std::max_element( node->sensitive_stdin_bits.begin(), node->sensitive_stdin_bits.end() );
            if ( max_it != node->sensitive_stdin_bits.end() ) {
                loop_props.max = std::max( loop_props.max, *max_it );
            }

            loop_props.sensitive_stdin_bit_counts.push_back( node->sensitive_stdin_bits.size() );
        }

        node = node->predecessor;
    }

    for ( const auto& [ loop_head_id, body ] : loop_to_props ) {
        auto loading_props = loading_loops.at( loop_head_id );
        auto& dependencies = dependencies_by_loading[ loop_head_id ];

        natural_32_bit loaded_bits = loading_props.max - loading_props.min;
        double per_loop = double( loaded_bits ) / double( loading_props.loop_count );
        dependencies.average_bits_per_loop.add( per_loop );

        bool loop_head_end_direction = loop_heads_ending.at( loop_head_id );

        for ( const auto& [ body_id, props ] : body ) {
            auto& body_props = dependencies.bit_values[ body_id ];
            natural_32_bit minimal_offset = props.min - loading_props.min;
            INVARIANT( minimal_offset >= 0 );
            body_props.minimal_bit_offset = std::min( body_props.minimal_bit_offset, minimal_offset );

            for ( const auto& count : props.sensitive_stdin_bit_counts ) {
                body_props.average_bit_size.add( count );
            }

            for ( bool direction : { true, false } ) {
                node_direction node_id_direction = { body_id, direction };

                if ( matrix.contains( node_id_direction ) ) {
                    dependencies.bodies.insert( node_id_direction );
                    dependencies.end_direction = loop_head_end_direction;
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_dependencies_by_loops( const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                               const loop_endings& loop_heads_ending )
{
    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        location_id::id_type loop_head_id = loop_head.id;
        if ( !loop_heads_ending.contains( loop_head_id ) || dependencies_by_loading.contains( loop_head_id ) ) {
            continue;
        }

        bool loop_head_end_direction = loop_heads_ending.at( loop_head_id );
        node_direction loop_head_direction = { loop_head_id, loop_head_end_direction };

        std::unordered_set< location_id::id_type > all_ids;
        all_ids.insert( loop_head_id );
        for ( const auto& loop_body_id : loop_bodies ) {
            all_ids.insert( loop_body_id.id );
        }

        dependent_loop_properties& props = dependencies_by_loops.get_props( all_ids, loop_head_id );

        props.heads[ loop_head_direction ].count++;

        for ( const auto& body : loop_bodies ) {
            for ( bool direction : { true, false } ) {
                node_direction node_id_direction = { body.id, direction };

                for ( const auto& [ head, _ ] : props.heads ) {
                    if ( head.node_id == body.id ) {
                        continue;
                    }
                }

                if ( matrix.contains( node_id_direction ) ) {
                    props.bodies.insert( node_id_direction );
                }
            }
        }
    }

    dependencies_by_loops.merge_properties();

    for ( auto it = dependencies_by_loops.loops.begin(); it != dependencies_by_loops.loops.end(); ) {
        bool removed = false;
        for ( const auto& [ head, _ ] : it->heads ) {
            if ( dependencies_by_loading.contains( head.node_id ) ) {
                it = dependencies_by_loops.loops.erase( it );
                removed = true;
                break;
            }
        }

        if ( !removed ) {
            ++it;
        }
    }

    std::sort( dependencies_by_loops.loops.begin(),
               dependencies_by_loops.loops.end(),
               []( const auto& a, const auto& b ) {
                   return a.get_smallest_loop_head_id() < b.get_smallest_loop_head_id();
               } );
}

// ------------------------------------------------------------------------------------------------
possible_path iid_node_dependence_props::generate_path_from_node_counts( const nodes_to_counts& path_counts )
{
    std::map< location_id::id_type, path_node_props > path;
    for ( const auto& [ id, counts ] : path_counts ) {
        if ( counts.left_count == 0 && counts.right_count == 0 ) {
            continue;
        }

        bool loop_head_end_direction = false;
        bool is_loop_head = false;

        for ( const auto& loop : dependencies_by_loops.loops ) {
            for ( const auto& [ head, _ ] : loop.heads ) {
                if ( head.node_id == id ) {
                    is_loop_head = true;
                    loop_head_end_direction = head.branching_direction;
                }
            }
        }

        auto it_loading = dependencies_by_loading.find( id );
        if ( it_loading != dependencies_by_loading.end() ) {
            is_loop_head = true;
            loop_head_end_direction = it_loading->second.end_direction;
        }

        path_node_props props = { counts, is_loop_head, loop_head_end_direction };
        path.emplace( id, props );
    }

    return possible_path( path );
}

// ------------------------------------------------------------------------------------------------
std::set< location_id::id_type > iid_node_dependence_props::get_loop_heads( bool include_loading_loops )
{
    std::set< location_id::id_type > loop_heads;
    for ( const auto& props : dependencies_by_loops.loops ) {
        for ( const auto& [ head, _ ] : props.heads ) {
            loop_heads.insert( head.node_id );
        }
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
void iid_dependencies::update_non_iid_nodes( sensitivity_analysis& sensitivity )
{
    for ( branching_node* node : sensitivity.get_changed_nodes() ) {
        if ( node->is_did_branching() ) {
            location_id::id_type location_id = node->get_location_id().id;
            if ( non_iid_nodes.insert( location_id ).second ) {
                id_to_equation_map.erase( location_id );
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_dependencies::process_node_dependence( branching_node* node )
{
    TMPROF_BLOCK();

    if ( non_iid_nodes.contains( node->get_location_id().id ) )
        return;

    iid_node_dependence_props& props = id_to_equation_map[ node->get_location_id().id ];
    props.process_node( node );
}

// ------------------------------------------------------------------------------------------------
void iid_dependencies::remove_node_dependence( location_id::id_type id )
{
    auto it = id_to_equation_map.find( id );
    if ( it != id_to_equation_map.end() ) {
        iid_node_generations_stats& stats = it->second.get_generations_stats();
        stats.state = generation_state::STATE_COVERED;

        if ( iid_dependencies::generate_more_data_after_coverage && !it->second.is_equal_branching_predicate() ) {
            stats.state = generation_state::STATE_GENERATION_MORE;
            int max_generation_after_covered = std::max( iid_dependencies::minimal_max_generation_after_covered,
                                                         stats.successful_generations / 2 );
            stats.generated_after_covered_max = max_generation_after_covered;
        }
    }
}

// ------------------------------------------------------------------------------------------------
iid_node_dependence_props& iid_dependencies::get_props( location_id::id_type id )
{
    return id_to_equation_map.at( id );
}

// ------------------------------------------------------------------------------------------------
std::vector< location_id::id_type > iid_dependencies::get_iid_nodes()
{
    std::vector< location_id::id_type > result;
    for ( const auto& [ key, _ ] : id_to_equation_map ) {
        result.push_back( key );
    }

    std::sort( result.begin(), result.end() );
    return result;
}

// ------------------------------------------------------------------------------------------------
std::optional< location_id::id_type > iid_dependencies::get_next_iid_node()
{
    bool previous_needs_more_data = false;
    for ( auto it = id_to_equation_map.rbegin(); it != id_to_equation_map.rend(); ++it ) {
        iid_node_dependence_props& props = it->second;

        if ( previous_needs_more_data ) {
            props.set_as_generating_for_other_node( iid_dependencies::minimal_max_generation_for_other_node );
            previous_needs_more_data = false;
        }

        if ( props.too_much_failed_in_row( iid_dependencies::max_failed_generations_in_row ) ) {
            props.get_generations_stats().failed_generations_in_row = 0;
            bool is_first = std::next( it ) == id_to_equation_map.rend();

            failed_generation_method method = props.get_method_for_failed_generation( is_first );

            if ( method == failed_generation_method::METHOD_GENERATE_FROM_OTHER_NODE ) {
                previous_needs_more_data = true;
            }
        }
    }

    std::optional< location_id::id_type > best_id = std::nullopt;

    for ( const auto& [ id, props ] : id_to_equation_map ) {
        if ( props.should_generate() ) {
            return id;
        }
    }

    return best_id;
}

//                               non member functions
// ------------------------------------------------------------------------------------------------
std::vector< node_direction > get_path( branching_node* node )
{
    std::vector< node_direction > result;

    branching_node* current = node;
    while ( current != nullptr ) {
        branching_node* predecessor = current->predecessor;
        if ( predecessor != nullptr ) {
            node_direction nav = { predecessor->get_location_id().id,
                                   predecessor->successor_direction( current ) };
            result.push_back( nav );
        }
        current = predecessor;
    }

    return result;
}

} // namespace fuzzing
