#include <fuzzing/fuzzer.hpp>
#include <fuzzing/iid_vector_analysis.hpp>
#include <utility/timeprof.hpp>

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::process_node( branching_node* end_node ) 
{
    loop_endings loop_heads_ending = get_loop_heads_ending( end_node );
    compute_dependencies_by_loading( end_node, loop_heads_ending );
    compute_dependencies_by_loops( end_node, loop_heads_ending );
}

// ------------------------------------------------------------------------------------------------
std::map< location_id, bool > fuzzing::iid_node_dependence_props::get_loop_heads_ending( branching_node* end_node ) const
{
    std::unordered_map< location_id, std::unordered_set< location_id > > loop_heads_to_bodies;
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
        const auto& loop_bodies = loop_heads_to_bodies[ loop_head_id ];

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
                                                                          const loop_endings& loop_heads_ending )
{}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_node_dependence_props::compute_dependencies_by_loops( branching_node* end_node,
                                                                        const loop_endings& loop_heads_ending )
{}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_dependencies::update_non_iid_nodes( const sensitivity_analysis& sensitivity ) {}

// ------------------------------------------------------------------------------------------------
void fuzzing::iid_dependencies::process_node_dependence( branching_node* node )
{
    TMPROF_BLOCK();

    if ( non_iid_nodes.contains( node->get_location_id() ) )
        return;
}
