#include <fuzzing/gradient_descent.hpp>
#include <fuzzing/iid_node_dependencies.hpp>
#include <utility/timeprof.hpp>

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
std::vector< fuzzing::node_direction > fuzzing::iid_node_dependence_props::get_path( branching_node* node ) const
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

    std::vector< std::pair< int, node_direction > > path = weights_to_path( weights );
    for ( const auto& [ value, nav ] : path ) {
        std::cout << "Node ID: " << nav.node_id.id << ", Direction: " << nav.direction
                  << ", Value: " << value << std::endl;
    }

    return weights;
}


std::vector< std::pair< int, fuzzing::node_direction > >
fuzzing::iid_node_dependence_props::weights_to_path( std::vector< float > const& weights ) const
{
    int path_size = get_possible_depth();

    if ( path_size == 0 || weights.empty() ) {
        return {};
    }

    float weights_sum = std::accumulate( weights.begin(), weights.end(), 0.0f );
    std::vector< std::pair< int, node_direction > > path;

    for ( int i = 0; i < weights.size(); ++i ) {
        float value = static_cast< float >( path_size ) * weights[ i ] / weights_sum;
        path.push_back( { static_cast< int >( value ), *std::next( interesting_nodes.begin(), i ) } );
    }

    return path;
}


/**
 * @brief Calculates the depth of a given branching node in the tree.
 *
 * This function traverses the tree from the given node to the root,
 * counting the number of edges (or levels) to determine the depth of the node.
 *
 * @param node A pointer to the branching_node whose depth is to be calculated.
 * @return The depth of the node as an integer.
 */
int fuzzing::iid_node_dependence_props::get_node_depth( branching_node* node ) const
{
    int depth = 0;
    branching_node* current = node;
    while ( current != nullptr ) {
        current = current->predecessor;
        ++depth;
    }

    return depth;
}


/**
 * @brief Updates the mean depth value for a given branching node.
 *
 * This function calculates the depth of the provided branching node and updates
 * the mean depth value associated with the node's best coverage value. The mean
 * depth is updated incrementally using the formula:
 *
 *     new_mean = current_mean + (depth - current_mean) / count
 *
 * where `depth` is the depth of the node, `current_mean` is the current mean depth,
 * and `count` is the number of times the mean has been updated.
 *
 * @param node A pointer to the branching node whose mean depth value is to be updated.
 */
void fuzzing::iid_node_dependence_props::update_value_to_mean_depth( branching_node* node )
{
    int depth = get_node_depth( node );
    iid_value_props& value_props = value_to_mean_depth[ node->best_coverage_value ];
    value_props.mean_depth = value_props.mean_depth + ( depth - value_props.mean_depth ) / ++value_props.value_counts;
}


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
    }

    props.add_equation( node );
    props.update_value_to_mean_depth( node );
}