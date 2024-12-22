#include <fuzzing/fuzzer.hpp>
#include <fuzzing/iid_vector_analysis.hpp>
#include <utility/timeprof.hpp>

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::process_node( branching_node* end_node )
{
    loop_head_to_bodies_t loop_heads_to_bodies;
    std::vector< fuzzer::loop_boundary_props > loops;
    fuzzing::fuzzer::detect_loops_along_path_to_node( end_node, loop_heads_to_bodies, &loops );

    loop_endings loop_heads_ending = get_loop_heads_ending( end_node, loop_heads_to_bodies, loops );

    compute_dependencies_by_loading( end_node, loop_heads_to_bodies, loop_heads_ending );
    compute_dependencies_by_loops( loop_heads_to_bodies, loop_heads_ending );
}

// ------------------------------------------------------------------------------------------------
std::map< location_id, bool > fuzzing::iid_node_dependence_props::get_loop_heads_ending(
    branching_node* end_node,
    const loop_head_to_bodies_t& loop_heads_to_bodies,
    const std::vector< fuzzer::loop_boundary_props >& loops ) const
{
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

        for ( const auto& bit_index : node->sensitive_stdin_bits ) {
            for ( const auto& [ loop_head, values ] : loading_loops ) {
                if ( !loop_heads_ending.contains( loop_head ) ) {
                    continue;
                }

                bool loop_head_direction = loop_heads_ending.at( loop_head );

                auto& [ min, max ] = values;
                if ( bit_index >= min && bit_index <= max ) {
                    dependencies_by_loading[ { loop_head, loop_head_direction } ].emplace( node_id, true );
                    dependencies_by_loading[ { loop_head, loop_head_direction } ].emplace( node_id, false );
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
            dependencies_by_loops[ { loop_head, loop_head_end_direction } ].emplace( body, true );
            dependencies_by_loops[ { loop_head, loop_head_end_direction } ].emplace( body, false );
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
