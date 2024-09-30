#include <fuzzing/gradient_descent.hpp>
#include <fuzzing/iid_node_dependencies.hpp>
#include <utility/timeprof.hpp>


/**
 * @brief Processes a branching node to update its properties.
 * 
 * This function updates the mean depth and direction counts of the given branching node.
 * 
 * @param node A pointer to the branching node to be processed.
 */
void fuzzing::iid_value_props::process_node( branching_node* node ) 
{
    update_mean_depth( node );
    update_direction_counts( node );
}


/**
 * @brief Updates the mean depth of a branching node.
 *
 * This function recalculates the mean depth of a branching node using the 
 * incremental average formula. It retrieves the depth of the provided node 
 * and updates the mean depth accordingly.
 *
 * @param node A pointer to the branching_node whose depth is to be used 
 *             for updating the mean depth.
 */
void fuzzing::iid_value_props::update_mean_depth( branching_node* node )
{
    int depth = node->get_depth();
    mean_depth = mean_depth + ( depth - mean_depth ) / ++value_counts;
}


/**
 * @brief Updates the direction counts for a given branching node.
 *
 * This function calculates the direction counts for the path of the given branching node
 * and updates the minimum and maximum statistics for each direction.
 *
 * @param node A pointer to the branching node for which the direction counts are to be updated.
 */
void fuzzing::iid_value_props::update_direction_counts( branching_node* node ) 
{
    std::vector< node_direction > path = get_path( node );

    std::map< node_direction, int > direction_counts;
    for ( const node_direction& nav : path ) {
        direction_counts[ nav ]++;
    }

    for ( auto& [ direction, stats ] : direction_statistics ) {
        std::get< 0 >( stats ) = std::min(direction_counts[ direction ], std::get< 0 >( stats ));
        std::get< 1 >( stats ) = std::max(direction_counts[ direction ], std::get< 1 >( stats ));
    }
}


/**
 * @brief Three-way comparison for node_direction.
 *
 * @param other The other node_direction object to compare with.
 * @return std::strong_ordering Result of the comparison.
 */
auto fuzzing::node_direction::operator<=>( node_direction const& other ) const
{
    if ( auto const cmp = node_id.id <=> other.node_id.id; cmp != 0 )
        return cmp;

    return direction <=> other.direction;
}


/**
 * @brief Equality operator for node_direction.
 *
 * Compares two node_direction objects for equality based on their node_id and direction.
 *
 * @param other The other node_direction object to compare with.
 * @return true if both node_id and direction are equal, false otherwise.
 */
bool fuzzing::node_direction::operator==( node_direction const& other ) const
{
    return node_id.id == other.node_id.id && direction == other.direction;
}


/**
 * @brief Updates the set of interesting nodes based on the given branching node.
 *
 * This function traverses the paths from the given branching node and updates the set of
 * interesting nodes by comparing the paths with all existing paths. If new interesting nodes are
 * found, the set is updated and the function returns true.
 *
 * @param node A pointer to the branching node from which to start the path traversal.
 * @return true if the set of interesting nodes was updated, false otherwise.
 */
bool fuzzing::iid_node_dependence_props::update_interesting_nodes( branching_node* node )
{
    TMPROF_BLOCK();

    bool set_changed = false;

    auto add_to_interesting = [ this, &set_changed ]( std::vector< node_direction >& nodes, int i ) {
        for ( ; i >= 0; --i ) {
            auto result = this->interesting_nodes.emplace( nodes[ i ] );
            if ( result.second ) {
                set_changed = true;
            }
        }
    };

    for ( const auto& end_node : all_paths ) {
        std::vector< node_direction > path_1 = get_path( node );
        std::vector< node_direction > path_2 = get_path( end_node );

        if ( path_1.empty() || path_2.empty() )
            continue;

        ASSUMPTION( path_1.back() == path_2.back() );

        std::size_t i_1 = path_1.size() - 1;
        std::size_t i_2 = path_2.size() - 1;

        while ( i_1 > 0 && i_2 > 0 && path_1[ i_1 ] == path_2[ i_2 ] ) {
            --i_1;
            --i_2;
        }

        add_to_interesting( path_1, i_1 );
        add_to_interesting( path_2, i_2 );
    }

    return set_changed;
}


/**
 * @brief Recomputes the matrix of IID dependence properties.
 *
 * This function clears the current matrix and best values, then iterates
 * through all paths to add equations to the matrix. If there are no paths,
 * the function returns immediately.
 *
 * @note The matrix clearing could be optimized in the future.
 */
void fuzzing::iid_node_dependence_props::recompute_matrix()
{
    TMPROF_BLOCK();

    if ( all_paths.empty() )
        return;

    matrix.clear(); // This could be done better, but for now it's fine
    best_values.clear();

    for ( const auto& path : all_paths ) {
        add_equation( path );
    }
}


/**
 * @brief Adds an equation to the IID dependence properties based on the given branching path.
 *
 * This function updates the internal matrix and best values with the direction counts of
 * interesting nodes encountered in the path.
 *
 * @param path A pointer to the branching_node representing the path to be processed.
 */
void fuzzing::iid_node_dependence_props::add_equation( branching_node* path )
{
    TMPROF_BLOCK();

    std::map< node_direction, int > directions_in_path;
    for ( const node_direction& navigation : interesting_nodes ) {
        directions_in_path[ navigation ] = 0;
    }

    std::vector< node_direction > path_nodes = get_path( path );

    for ( const node_direction& nav : path_nodes ) {
        if ( interesting_nodes.contains( nav ) ) {
            directions_in_path[ nav ]++;
        }
    }

    std::vector< float > values_in_path;
    for ( const auto& [ direction, count ] : directions_in_path ) {
        values_in_path.push_back( count );
    }

    matrix.push_back( values_in_path );
    best_values.push_back( path->best_coverage_value );
}


/**
 * @brief Approximates a matrix using gradient descent optimization.
 *
 * This function utilizes the GradientDescent class to optimize the given matrix
 * and best values, returning a vector of optimized weights.
 *
 * @return A vector of floats representing the optimized weights.
 */
std::vector< float > fuzzing::iid_node_dependence_props::approximate_matrix() const
{
    GradientDescent gd( matrix, best_values );
    std::vector< float > weights = gd.optimize();
    return weights;
}


std::map< fuzzing::node_direction, int >
fuzzing::iid_node_dependence_props::weights_to_path( std::vector< float > const& weights ) const
{
    int path_size = get_possible_depth();

    if ( path_size == 0 || weights.empty() ) {
        return {};
    }

    float weights_sum = std::accumulate( weights.begin(), weights.end(), 0.0f );
    std::map< node_direction, int > path;

    for ( int i = 0; i < weights.size(); ++i ) {
        float value = static_cast< float >( path_size ) * weights[ i ] / weights_sum;
        path[*std::next( interesting_nodes.begin(), i )] = static_cast< int >( value );
    }

    return path;
}


/**
 * @brief Computes the possible depth based on the value to mean depth mapping.
 *
 * This function calculates the possible depth by examining the `value_to_mean_depth` map.
 * If the map is empty, it returns 0. If the map contains only one element, it returns the mean depth
 * of that element. If the map contains more than one element, it calculates the depth using linear
 * interpolation based on the first two elements in the map.
 *
 * @return The computed possible depth.
 */
int fuzzing::iid_node_dependence_props::get_possible_depth() const 
{
    if ( value_to_mean_depth.empty() ) {
        return 0;
    }

    if (value_to_mean_depth.size() == 1) {
        return value_to_mean_depth.begin()->second.mean_depth;
    }

    auto it = value_to_mean_depth.begin();
    int first_depth = it->second.mean_depth;
    float first_value = it->first;
    ++it;
    int second_depth = it->second.mean_depth;
    float second_value = it->first;

    if (first_value == second_value) {
        return first_depth;
    }

    float slope = static_cast<float>(second_depth - first_depth) / (second_value - first_value);
    float intercept = first_depth - slope * first_value;

    int result = static_cast<int>(slope * 0 + intercept);
    return result;
}


/**
 * @brief Generates a path based on node dependencies.
 *
 * This function approximates a matrix to generate weights and then converts 
 * these weights into a path represented as a map of node directions to integers.
 *
 * @return A map where the keys are node directions and the values are integers 
 *         representing the path.
 */
std::map< fuzzing::node_direction, int > fuzzing::iid_node_dependence_props::generate_path() const
{
    std::vector< float > weights = approximate_matrix();
    std::map< fuzzing::node_direction, int > path = weights_to_path( weights );
    return path;
}

/**
 * @brief Updates the set of non-IID nodes based on sensitivity analysis.
 *
 * This function iterates through the nodes that have changed according to the
 * provided sensitivity analysis. For each node that has undergone branching,
 * it retrieves the node's location ID and attempts to insert it into the set
 * of non-IID nodes. If the insertion is successful, it also removes the
 * corresponding entry from the ID-to-equation map.
 *
 * @param sensitivity A reference to the sensitivity analysis object that
 *                    provides the changed nodes.
 */
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


/**
 * @brief Processes the dependence of a given branching node.
 *
 * This function processes the dependence of a branching node by updating
 * the internal state and properties associated with the node's location ID.
 * It ensures that non-IID nodes are skipped, updates the list of all paths,
 * and recomputes the matrix if the node is deemed interesting. Additionally,
 * it adds the node to the equation map.
 *
 * @param node A pointer to the branching node to be processed.
 */
void fuzzing::iid_dependencies::process_node_dependence( branching_node* node )
{
    TMPROF_BLOCK();

    if ( non_iid_nodes.contains( node->get_location_id() ) )
        return;

    iid_node_dependence_props& props = id_to_equation_map[ node->get_location_id() ];

    props.all_paths.push_back( node );

    if ( props.update_interesting_nodes( node ) ) {
        props.recompute_matrix();
    } else {
        props.add_equation( node );
    }

    iid_value_props& value_props = props.value_to_mean_depth[ node->best_coverage_value ];
    value_props.process_node( node );
}


/**
 * @brief Retrieves the path of node navigations from the given branching node to the root.
 *
 * This function constructs a vector of `node_direction` objects representing the path
 * from the specified branching node to the root node. Each `node_direction` object
 * contains the location ID of the predecessor node and the direction to the current node.
 *
 * @param node A pointer to the starting branching node.
 * @return A vector of `node_direction` objects representing the path from the given node to the
 * root.
 */
std::vector< fuzzing::node_direction > fuzzing::get_path( branching_node* node )
{
    std::vector< node_direction > path;

    branching_node* current = node;
    while ( current != nullptr ) {
        branching_node* predecessor = current->predecessor;
        if ( predecessor != nullptr ) {
            node_direction nav = { predecessor->get_location_id(),
                                    predecessor->successor_direction( current ) };
            path.push_back( nav );
        }
        current = predecessor;
    }

    return path;
}