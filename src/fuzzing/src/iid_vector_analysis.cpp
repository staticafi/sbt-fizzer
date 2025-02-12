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

//                                       node_props_in_path
// ------------------------------------------------------------------------------------------------
bool node_props_in_path::get_desired_direction() const
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
bool node_props_in_path::can_go_direction( bool direction ) const
{
    if ( direction ) {
        return taken_counts.right_count < computed_counts.right_count;
    } else {
        return taken_counts.left_count < computed_counts.left_count;
    }
}

// ------------------------------------------------------------------------------------------------
void node_props_in_path::go_direction( bool direction )
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
bool node_props_in_path::can_take_next_direction() const
{
    return taken_counts.left_count < computed_counts.left_count ||
           taken_counts.right_count < computed_counts.right_count;
}

// ------------------------------------------------------------------------------------------------
float_32_bit node_props_in_path::get_false_direction_probability() const
{
    INVARIANT( computed_counts.left_count + computed_counts.right_count > 0 );

    return float_32_bit( computed_counts.left_count ) /
           ( computed_counts.left_count + computed_counts.right_count );
}

// ------------------------------------------------------------------------------------------------
bool node_props_in_path::get_preferred_direction_loop_head() const
{
    auto is_depleted = []( int computed, int taken ) { return computed == taken; };

    if ( !loop_head_end_direction ) {
        return !is_depleted( computed_counts.right_count, taken_counts.right_count );
    } else {
        return is_depleted( computed_counts.left_count, taken_counts.left_count );
    }
}

//                                         generated_path
// ------------------------------------------------------------------------------------------------
bool generated_path::contains( location_id::id_type id ) const { return path.contains( id ); }

// ------------------------------------------------------------------------------------------------
std::map< location_id::id_type, node_props_in_path > generated_path::get_path() const { return path; }

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

//                                     node_id_with_direction
// ------------------------------------------------------------------------------------------------
auto node_id_with_direction::operator<=>( node_id_with_direction const& other ) const
{
    if ( auto const cmp = node_id <=> other.node_id; cmp != 0 )
        return cmp;

    return branching_direction <=> other.branching_direction;
}

//                                    loop_properties
// ------------------------------------------------------------------------------------------------
bool fuzzing::loop_properties::is_same( const std::set< location_id::id_type >& other_ids ) const
{
    return get_all_ids() == other_ids;
}

// ------------------------------------------------------------------------------------------------
std::set< location_id::id_type > fuzzing::loop_properties::get_all_ids() const
{
    std::set< location_id::id_type > all_ids;

    for ( const auto& [ head, props ] : heads ) {
        all_ids.insert( head.node_id );
    }

    for ( const auto& body : bodies ) {
        all_ids.insert( body.node_id );
    }

    return all_ids;
}

// ------------------------------------------------------------------------------------------------
std::set< location_id::id_type > fuzzing::loop_properties::get_loop_head_ids() const
{
    std::set< location_id::id_type > loop_head_ids;

    for ( const auto& [ head, props ] : heads ) {
        loop_head_ids.insert( head.node_id );
    }

    return loop_head_ids;
}

// ------------------------------------------------------------------------------------------------
std::set< location_id::id_type > fuzzing::loop_properties::get_body_ids() const
{
    std::set< location_id::id_type > body_ids;

    for ( const auto& body : bodies ) {
        body_ids.insert( body.node_id );
    }

    return body_ids;
}

// ------------------------------------------------------------------------------------------------
location_id::id_type fuzzing::loop_properties::get_smallest_loop_head_id() const
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
void fuzzing::loop_properties::set_chosen_loop_head()
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

//                                     loop_dependencies
// ------------------------------------------------------------------------------------------------
loop_properties& fuzzing::loop_dependencies::get_props( const std::set< location_id::id_type >& ids,
                                                        location_id::id_type loop_head_id )
{
    for ( loop_properties& loop : loops ) {
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
void fuzzing::loop_dependencies::merge_properties()
{
    for ( auto it = loops.begin(); it != loops.end(); it++ ) {
        std::set< location_id::id_type > head_ids = it->get_loop_head_ids();

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
        std::set< location_id::id_type > head_ids = it->get_loop_head_ids();

        for ( auto body_it = it->bodies.begin(); body_it != it->bodies.end(); ) {
            if ( head_ids.contains( body_it->node_id ) ) {
                body_it = it->bodies.erase( body_it );
            } else {
                ++body_it;
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
loop_properties& fuzzing::loop_dependencies::get_props_by_loop_head_id( location_id::id_type loop_head_id )
{
    for ( loop_properties& loop : loops ) {
        for ( const auto& [ head, props ] : loop.heads ) {
            if ( head.node_id == loop_head_id ) {
                return loop;
            }
        }
    }

    throw std::runtime_error( "Loop head not found: " + std::to_string( loop_head_id ) );
}

//                                       equation_matrix
// ------------------------------------------------------------------------------------------------
equation_matrix equation_matrix::get_submatrix( std::set< node_id_with_direction > const& subset, bool unique ) const
{
    equation_matrix result;
    result.nodes = subset;

    for ( int i = 0; i < matrix.size(); ++i ) {
        const equation& row = matrix[ i ];

        std::vector< int > new_row_values;
        for ( const node_id_with_direction& nav : subset ) {
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

    std::vector< node_id_with_direction > path = get_path( end_node );
    bool new_node = false;
    for ( const node_id_with_direction& nav : path ) {
        for ( bool direction : { true, false } ) {
            auto [ it, inserted ] = nodes.insert( { nav.node_id, direction } );
            new_node |= inserted;
        }
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

    std::map< node_id_with_direction, int > directions_in_path;
    for ( const node_id_with_direction& navigation : nodes ) {
        directions_in_path[ navigation ] = 0;
    }

    std::vector< node_id_with_direction > path_nodes = get_path( end_node );

    for ( const node_id_with_direction& nav : path_nodes ) {
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
bool equation_matrix::contains( node_id_with_direction const& node ) const { return nodes.contains( node ); }

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
std::optional< equation >
equation_matrix::get_new_subset_counts_from_vectors( const std::vector< equation >& vectors,
                                                     int generation_count_after_covered,
                                                     const iid_node_generations_stats& stats )
{
    INVARIANT( !vectors.empty() );
    INVARIANT( vectors[ 0 ].values.size() == nodes.size() );

    bool generate_more_data = should_generate_more_data( stats.state );

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
                    float procents_to_add = 1 + iid_dependencies::percentage_to_add_to_path;

                    if ( stats.state == generation_state::STATE_GENERATING_ARTIFICIAL_DATA ) {
                        // new_path = new_path.add_to_positive( stats.generate_artificial_data_count );
                        // new_path = new_path + vector * stats.generate_artificial_data_count;
                        procents_to_add += stats.generate_artificial_data_count / 3.0;
                    }

                    new_path = new_path * procents_to_add;
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
    for ( const node_id_with_direction& nav : nodes ) {
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
generated_path iid_node_dependence_props::generate_probabilities()
{
    stats.method_calls++;

    std::set< node_id_with_direction > computation_subset = get_node_subsets_for_computation();
    if ( computation_subset.empty() || loop_to_properties.loops.empty() ) {
        return {};
    }

    TMPROF_BLOCK();
    stats.generation_starts++;
    equation_matrix submatrix = matrix.get_submatrix( computation_subset, true );

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

    std::optional< equation > new_subset_counts =
        submatrix.get_new_subset_counts_from_vectors( *best_vectors, stats.generated_after_covered, stats );

    if ( !new_subset_counts.has_value() ) {
        return return_empty_path();
    }

    nodes_to_counts node_counts = compute_node_counts( new_subset_counts.value(), computation_subset );
    generated_path path = generate_path_from_node_counts( node_counts );

    // std::cout << "Generated path: " << std::endl << path << std::endl;

    return return_path( path );
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::process_node( branching_node* end_node )
{
    loop_head_to_bodies_t loop_heads_to_bodies;
    loop_endings loop_heads_ending = get_loop_heads_ending( end_node, loop_heads_to_bodies );

    matrix.process_node( end_node );

    compute_dependencies_by_loops( loop_heads_to_bodies, loop_heads_ending );
    compute_dependencies_by_loading( end_node, loop_heads_to_bodies, loop_heads_ending );
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
    stats.generated_for_other_node_count++;
}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::set_as_generating_artificial_data( int minimal_max_generation_artificial_data )
{
    INVARIANT( stats.state == generation_state::STATE_NOT_COVERED );

    stats.state = generation_state::STATE_GENERATING_ARTIFICIAL_DATA;
    stats.generate_artificial_data_max = minimal_max_generation_artificial_data;
    stats.generate_artificial_data = 0;
    stats.generate_artificial_data_count++;
}

// ------------------------------------------------------------------------------------------------
failed_generation_method fuzzing::iid_node_dependence_props::get_method_for_failed_generation( bool is_first )
{
    failed_generation_method new_method;

    if ( !iid_dependencies::create_artificial_data ) {
        return failed_generation_method::METHOD_GENERATE_FROM_OTHER_NODE;
    } else if ( is_first ) {
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
void fuzzing::iid_node_dependence_props::combine_props( const iid_node_dependence_props& other )
{
    std::vector< loop_properties > loops_to_add;

    for ( const auto& other_loop : other.loop_to_properties.loops ) {
        for ( const auto& loop : loop_to_properties.loops ) {
            std::set< location_id::id_type > other_ids = other_loop.get_loop_head_ids();
            std::set< location_id::id_type > ids = loop.get_loop_head_ids();

            std::set< location_id::id_type > intersection;

            std::set_intersection( other_ids.begin(),
                                   other_ids.end(),
                                   ids.begin(),
                                   ids.end(),
                                   std::inserter( intersection, intersection.begin() ) );

            if ( !intersection.empty() ) {
                loops_to_add.push_back( other_loop );
            }
        }
    }

    for ( const auto& loop : loops_to_add ) {
        loop_to_properties.loops.push_back( loop );
    }

    loop_to_properties.merge_properties();
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::print_dependencies() const
{
    bool print_dependencies_by_loops = true;
    bool print_dependencies_by_loading = true;

    if ( !print_dependencies_by_loops && !print_dependencies_by_loading ) {
        return;
    }

    std::cout << "# Dependencies:" << std::endl;
    if ( print_dependencies_by_loops ) {
        std::cout << "## Dependencies by loops:" << std::endl;
        for ( const auto& loop : loop_to_properties.loops ) {
            if ( loop.is_loading_loop ) {
                continue;
            }

            std::cout << "Loop heads:" << std::endl;
            for ( const auto& [ head, head_props ] : loop.heads ) {
                std::cout << "- " << head << " (" << head_props.count << ")" << std::endl;
            }

            std::cout << "Loop bodies:" << std::endl;
            for ( const auto& body : loop.bodies ) {
                std::cout << "- " << body << std::endl;
            }

            if ( loop.is_loading_loop ) {
                std::cout << "Loading loop" << std::endl;
                std::cout << "Average bits per loop: " << loop.loaded_bits_per_loop.mean << std::endl;
                for ( const auto& [ body, body_props ] : loop.bits_read_by_node ) {
                    std::cout << "- " << body << ", Bits: " << body_props.average_bits_read.mean
                              << ", offset: " << body_props.minimal_bit_offset << std::endl;
                }
            }
        }
    }

    if ( print_dependencies_by_loading ) {
        std::cout << "## Dependencies by loading:" << std::endl;
        for ( const auto& loop : loop_to_properties.loops ) {
            if ( !loop.is_loading_loop ) {
                continue;
            }

            std::cout << "Loop heads:" << std::endl;
            for ( const auto& [ head, head_props ] : loop.heads ) {
                std::cout << "- " << head << " (" << head_props.count << ")" << std::endl;
            }

            std::cout << "Loop bodies:" << std::endl;
            for ( const auto& body : loop.bodies ) {
                std::cout << "- " << body << std::endl;
            }

            std::cout << "Dependent nodes:" << std::endl;
            for ( const auto& [ body, body_props ] : loop.bits_read_by_node ) {
                std::cout << "- " << body << ", Bits: " << body_props.average_bits_read.mean
                          << ", offset: " << body_props.minimal_bit_offset << std::endl;
            }

            std::cout << "Loaded bits per loop: " << loop.loaded_bits_per_loop.mean << std::endl;
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
generated_path iid_node_dependence_props::return_empty_path()
{
    stats.failed_generations++;
    stats.failed_generations_in_row++;
    return generated_path();
}

// ------------------------------------------------------------------------------------------------
generated_path iid_node_dependence_props::return_path( const generated_path& path )
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
void iid_node_dependence_props::compute_node_counts_for_nested_loops( nodes_to_counts& path_counts,
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
        loop_properties& props = loop_to_properties.get_props_by_loop_head_id( node_id );

        for ( auto& [ head, _ ] : props.heads ) {
            auto& [ left_count, right_count ] = path_counts[ head.node_id ];

            if ( head.branching_direction ) {
                left_count = count / highest_count;
            } else {
                right_count = count / highest_count;
            }
        }
    }


    loop_properties& props = loop_to_properties.get_props_by_loop_head_id( loop_head_id );
    for ( auto& [ head, _ ] : props.heads ) {
        if ( head.branching_direction ) {
            path_counts[ head.node_id ] = { highest_count, 1 };
        } else {
            path_counts[ head.node_id ] = { 1, highest_count };
        }
    }
}

// ------------------------------------------------------------------------------------------------
int fuzzing::iid_node_dependence_props::compute_loading_loop_interation( nodes_to_counts& path_counts,
                                                                         location_id::id_type id,
                                                                         const std::set< location_id::id_type >& loop_heads,
                                                                         const loop_properties& props,
                                                                         float loaded_bits_per_loop )
{
    float loaded_per_loop = props.loaded_bits_per_loop.mean - loaded_bits_per_loop;
    if ( loaded_per_loop <= 0 ) {
        loaded_per_loop = 8;
    }

    float average_bits = props.bits_read_by_node.at( id ).average_bits_read.mean;
    natural_32_bit offset = props.bits_read_by_node.at( id ).minimal_bit_offset;

    bool is_loop_head = true;
    if ( !loop_heads.contains( id ) ) {
        for ( const auto& loop : loop_to_properties.loops ) {
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
void iid_node_dependence_props::compute_node_counts_for_loading_loops( nodes_to_counts& path_counts,
                                                                       const equation& path,
                                                                       const std::set< location_id::id_type >& loop_heads )
{
    for ( const auto& loop_props : std::ranges::views::reverse( loop_to_properties.loops ) ) {
        if ( !loop_props.is_loading_loop ) {
            continue;
        }

        int loop_count = 1;
        std::map< location_id::id_type, int > child_loop_counts;

        float loaded_bits_per_loop = 0.0f;

        for ( const auto& body : loop_props.bodies ) {
            if ( !loop_heads.contains( body.node_id ) ) {
                continue;
            }


            const loop_properties& body_props = loop_to_properties.get_props_by_loop_head_id( body.node_id );
            if ( body_props.is_loading_loop ) {
                // loaded_bits_per_loop += body_props.loaded_bits_per_loop.mean;
            }
        }

        for ( const auto& body : loop_props.nodes_dependent_by_loading ) {
            if ( !path_counts.contains( body.node_id ) ) {
                continue;
            }

            int minimal_count = compute_loading_loop_interation(
                path_counts, body.node_id, loop_heads, loop_props, loaded_bits_per_loop );
            loop_count = std::max( loop_count, minimal_count );
        }

        for ( const auto& body : loop_props.bodies ) {
            if ( loop_heads.contains( body.node_id ) ) {
                const auto& inner_loop_props = loop_to_properties.get_props_by_loop_head_id( body.node_id );
                if ( inner_loop_props.is_loading_loop ) {
                    loop_count = 1;
                }
            } 
        }

        for ( const auto& body : loop_props.bodies ) {
            auto& [ left_count, right_count ] = path_counts[ body.node_id ];

            if ( loop_heads.contains( body.node_id ) ) {
                child_loop_counts[ body.node_id ] = std::max( left_count, right_count );
            } else {
                loop_count = std::max( loop_count, left_count + right_count );
            }
        }

        if ( child_loop_counts.empty() ) {
            for ( const auto& [ head, _ ] : loop_props.heads ) {
                int end_count = head == ( *loop_props.chosen_loop_head ) ? 1 : 0;

                if ( head.branching_direction ) {
                    path_counts[ head.node_id ] = { loop_count, end_count };
                } else {
                    path_counts[ head.node_id ] = { end_count, loop_count };
                }
            }
        } else {
            compute_node_counts_for_nested_loops( path_counts,
                                                  child_loop_counts,
                                                  ( *loop_props.chosen_loop_head ).node_id,
                                                  loop_count,
                                                  iid_dependencies::random_nested_loop_counts );
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_node_counts_for_loops( nodes_to_counts& path_counts,
                                                               const equation& path,
                                                               const std::set< location_id::id_type >& loop_heads )
{
    for ( const auto& props : std::ranges::views::reverse( loop_to_properties.loops ) ) {
        if ( props.bodies.empty() || props.is_loading_loop ) {
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

        compute_node_counts_for_nested_loops( path_counts,
                                              child_loop_counts,
                                              ( *props.chosen_loop_head ).node_id,
                                              non_loop_child_max_count,
                                              iid_dependencies::random_nested_loop_counts );
    }
}

// ------------------------------------------------------------------------------------------------
nodes_to_counts iid_node_dependence_props::compute_node_counts( const equation& path,
                                                                std::set< node_id_with_direction > const& computation_subset )
{
    nodes_to_counts path_counts;

    std::vector< node_id_with_direction > leafs =
        std::vector< node_id_with_direction >( computation_subset.begin(), computation_subset.end() );
    INVARIANT( leafs.size() == path.values.size() );

    std::set< location_id::id_type > loop_heads = get_loop_heads( false );

    for ( auto& loop : loop_to_properties.loops ) {
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

    for ( const auto& loop_props : std::ranges::views::reverse( loop_to_properties.loops ) ) {
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

    compute_node_counts_for_loops( path_counts, path, loop_heads );
    loop_heads = get_loop_heads( true );
    compute_node_counts_for_loading_loops( path_counts, path, loop_heads );

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
std::set< node_id_with_direction > iid_node_dependence_props::get_node_subsets_for_computation()
{
    std::set< node_id_with_direction > computation_subset;
    auto loop_heads = get_loop_heads( false );

    for ( const auto& loop : loop_to_properties.loops ) {
        if ( loop.bodies.empty() || loop.is_loading_loop ) {
            continue;
        }

        for ( const auto& body : loop.bodies ) {
            location_id::id_type body_id = body.node_id;
            if ( !loop_heads.contains( body_id ) ) {
                computation_subset.insert( body );
            }
        }

        for ( const auto& [ head, _ ] : loop.heads ) {
            computation_subset.insert( { head.node_id, !head.branching_direction } );
        }
    }

    return computation_subset;
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
                                                                loop_head_to_loaded_bits_counter& loading_loops,
                                                                const loop_endings& loop_heads_ending )
{
    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        loading_loops[ loop_head.id ] = { std::numeric_limits< natural_32_bit >::max(),
                                          std::numeric_limits< natural_32_bit >::min() };
    }

    branching_node* node = end_node;
    branching_node* prev_node = nullptr;

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

        // Remove one loop count for branching that ends the loop
        prev_node = node->predecessor;
        if ( prev_node != nullptr ) {
            bool node_direction = prev_node->successor( true ).pointer == node;

            for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
                auto it = loop_heads_ending.find( loop_head.id );
                if ( it == loop_heads_ending.end() ) {
                    continue;
                }

                if ( loop_head.id == prev_node->get_location_id().id && it->second == node_direction ) {
                    auto& props = loading_loops[ loop_head.id ];
                    props.loop_count--;

                }
            }
        }

        node = prev_node;
    }

    // Remove all loops that did not load any data inside
    for ( auto it = loading_loops.begin(); it != loading_loops.end(); ) {
        if ( it->second.min == it->second.max ) {
            it = loading_loops.erase( it );
        } else {
            ++it;
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_node_dependence_props::compute_dependencies_by_loading( branching_node* end_node,
                                                                 const loop_head_to_bodies_t& loop_heads_to_bodies,
                                                                 const loop_endings& loop_heads_ending )
{
    loop_head_to_loaded_bits_counter loading_loops;
    compute_loading_loops( end_node, loop_heads_to_bodies, loading_loops, loop_heads_ending );

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
        loop_properties& dependencies = loop_to_properties.get_props_by_loop_head_id( loop_head_id );
        dependencies.is_loading_loop = true;

        natural_32_bit loaded_bits = loading_props.max - loading_props.min;
        double per_loop = double( loaded_bits ) / double( loading_props.loop_count );
        dependencies.loaded_bits_per_loop.add( per_loop );

        bool loop_head_end_direction = loop_heads_ending.at( loop_head_id );

        for ( const auto& [ body_id, props ] : body ) {
            auto& body_props = dependencies.bits_read_by_node[ body_id ];
            natural_32_bit minimal_offset = props.min - loading_props.min;
            INVARIANT( minimal_offset >= 0 );
            body_props.minimal_bit_offset = std::min( body_props.minimal_bit_offset, minimal_offset );

            for ( const auto& count : props.sensitive_stdin_bit_counts ) {
                body_props.average_bits_read.add( count );
            }

            for ( bool direction : { true, false } ) {
                node_id_with_direction node_id_direction = { body_id, direction };

                if ( matrix.contains( node_id_direction ) ) {
                    dependencies.nodes_dependent_by_loading.insert( node_id_direction );
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
        if ( !loop_heads_ending.contains( loop_head_id ) ) {
            continue;
        }

        bool loop_head_end_direction = loop_heads_ending.at( loop_head_id );
        node_id_with_direction loop_head_direction = { loop_head_id, loop_head_end_direction };

        std::set< location_id::id_type > all_ids;
        all_ids.insert( loop_head_id );
        for ( const auto& loop_body_id : loop_bodies ) {
            all_ids.insert( loop_body_id.id );
        }

        loop_properties& props = loop_to_properties.get_props( all_ids, loop_head_id );

        props.heads[ loop_head_direction ].count++;

        for ( const auto& body : loop_bodies ) {
            for ( bool direction : { true, false } ) {
                node_id_with_direction node_id_direction = { body.id, direction };

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

    loop_to_properties.merge_properties();

    std::sort( loop_to_properties.loops.begin(), loop_to_properties.loops.end(), []( const auto& a, const auto& b ) {
        return a.get_smallest_loop_head_id() < b.get_smallest_loop_head_id();
    } );
}

// ------------------------------------------------------------------------------------------------
generated_path iid_node_dependence_props::generate_path_from_node_counts( const nodes_to_counts& path_counts )
{
    std::map< location_id::id_type, node_props_in_path > path;
    for ( const auto& [ id, counts ] : path_counts ) {
        if ( counts.left_count == 0 && counts.right_count == 0 ) {
            continue;
        }

        bool loop_head_end_direction = false;
        bool is_loop_head = false;

        for ( const auto& loop : loop_to_properties.loops ) {
            for ( const auto& [ head, _ ] : loop.heads ) {
                if ( head.node_id == id ) {
                    is_loop_head = true;
                    loop_head_end_direction = head.branching_direction;
                }
            }
        }

        node_props_in_path props = { counts, is_loop_head, loop_head_end_direction };
        path.emplace( id, props );
    }

    return generated_path( path );
}

// ------------------------------------------------------------------------------------------------
std::set< location_id::id_type > iid_node_dependence_props::get_loop_heads( bool include_loading_loops )
{
    std::set< location_id::id_type > loop_heads;
    for ( const auto& props : loop_to_properties.loops ) {
        if ( props.is_loading_loop && !include_loading_loops ) {
            continue;
        }

        for ( const auto& [ head, _ ] : props.heads ) {
            loop_heads.insert( head.node_id );
        }
    }

    return loop_heads;
}

//                                 iid_dependencies
// ------------------------------------------------------------------------------------------------
void iid_dependencies::update_ignored_nodes( sensitivity_analysis& sensitivity )
{
    for ( branching_node* node : sensitivity.get_changed_nodes() ) {
        if ( node->is_did_branching() ) {
            location_id::id_type location_id = node->get_location_id().id;
            if ( ignored_node_ids.insert( location_id ).second ) {
                node_id_to_equation_map.erase( location_id );
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
void iid_dependencies::process_node_dependence( branching_node* node )
{
    TMPROF_BLOCK();

    if ( ignored_node_ids.contains( node->get_location_id().id ) )
        return;

    iid_node_dependence_props& props = node_id_to_equation_map[ node->get_location_id().id ];
    props.process_node( node );
}

// ------------------------------------------------------------------------------------------------
void iid_dependencies::remove_node_dependence( location_id::id_type id )
{
    auto it = node_id_to_equation_map.find( id );
    if ( it != node_id_to_equation_map.end() ) {
        iid_node_generations_stats& stats = it->second.get_generations_stats();
        stats.state = generation_state::STATE_COVERED;
        ignored_node_ids.insert( id );

        if ( it != node_id_to_equation_map.end() ) {
            auto next_it = std::next( it );
            next_it->second.combine_props( it->second );
        }

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
    return node_id_to_equation_map.at( id );
}

// ------------------------------------------------------------------------------------------------
std::vector< location_id::id_type > iid_dependencies::get_iid_nodes()
{
    std::vector< location_id::id_type > result;
    for ( const auto& [ key, _ ] : node_id_to_equation_map ) {
        result.push_back( key );
    }

    std::sort( result.begin(), result.end() );
    return result;
}

// ------------------------------------------------------------------------------------------------
std::optional< location_id::id_type > iid_dependencies::get_next_iid_node()
{
    bool previous_needs_more_data = false;
    for ( auto it = node_id_to_equation_map.rbegin(); it != node_id_to_equation_map.rend(); ++it ) {
        iid_node_dependence_props& props = it->second;

        if ( previous_needs_more_data ) {
            props.set_as_generating_for_other_node( iid_dependencies::minimal_max_generation_for_other_node );
            previous_needs_more_data = false;
        }

        if ( props.too_much_failed_in_row( iid_dependencies::max_failed_generations_in_row ) ) {
            props.get_generations_stats().failed_generations_in_row = 0;
            bool is_first = std::next( it ) == node_id_to_equation_map.rend();

            failed_generation_method method = props.get_method_for_failed_generation( is_first );

            if ( method == failed_generation_method::METHOD_GENERATE_FROM_OTHER_NODE ) {
                previous_needs_more_data = true;
            }
        }
    }

    std::optional< location_id::id_type > best_id = std::nullopt;

    for ( const auto& [ id, props ] : node_id_to_equation_map ) {
        if ( props.should_generate() ) {
            return id;
        }
    }

    return best_id;
}


// ------------------------------------------------------------------------------------------------
iid_vector_analysis_statistics fuzzing::iid_dependencies::get_stats() const
{
    iid_vector_analysis_statistics stats;

    iid_vector_analysis_statistics_per_node node_stats;
    for ( const auto& [ id, props ] : node_id_to_equation_map ) {
        node_stats.generation_stats = props.get_generations_stats();
        node_stats.loop_to_properties = props.get_dependencies_by_loops();

        stats.iid_nodes_stats[ id ] = node_stats;
    }

    stats.ignored_node_ids = std::vector< location_id::id_type >( ignored_node_ids.begin(),
                                                                  ignored_node_ids.end() );

    return stats;
}

//                               non member functions
// ------------------------------------------------------------------------------------------------
std::vector< node_id_with_direction > get_path( branching_node* node )
{
    std::vector< node_id_with_direction > result;

    branching_node* current = node;
    while ( current != nullptr ) {
        branching_node* predecessor = current->predecessor;
        if ( predecessor != nullptr ) {
            node_id_with_direction nav = { predecessor->get_location_id().id,
                                           predecessor->successor_direction( current ) };
            result.push_back( nav );
        }
        current = predecessor;
    }

    return result;
}

bool should_generate_more_data( const generation_state& state )
{
    return state == generation_state::STATE_GENERATION_MORE ||
           state == generation_state::STATE_GENERATION_DATA_FOR_NEXT_NODE ||
           state == generation_state::STATE_GENERATING_ARTIFICIAL_DATA;
}

} // namespace fuzzing
