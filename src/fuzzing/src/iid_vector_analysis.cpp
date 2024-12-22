#include <fuzzing/branching_node.hpp>
#include <fuzzing/fuzzer.hpp>
#include <fuzzing/iid_vector_analysis.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <iostream>
#include <string>
#include <utility/timeprof.hpp>

// ------------------------------------------------------------------------------------------------
auto fuzzing::node_direction::operator<=>( node_direction const& other ) const
{
    if ( auto const cmp = node_id.id <=> other.node_id.id; cmp != 0 )
        return cmp;

    return branching_direction <=> other.branching_direction;
}

// ------------------------------------------------------------------------------------------------
bool fuzzing::node_direction::operator==( node_direction const& other ) const
{
    return node_id.id == other.node_id.id && branching_direction == other.branching_direction;
}

// ------------------------------------------------------------------------------------------------
fuzzing::equation_matrix fuzzing::equation_matrix::get_submatrix( std::set< node_direction > const& subset, bool unique ) const
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
void fuzzing::equation_matrix::recompute_matrix() 
{
    TMPROF_BLOCK();

    matrix.clear();

    for ( branching_node* path : all_paths ) {
        add_equation( path );
    }
}

// ------------------------------------------------------------------------------------------------
std::unordered_map< location_id::id_type, float > fuzzing::iid_node_dependence_props::generate_probabilities()
{
    print_dependencies();
    matrix.print_matrix();

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