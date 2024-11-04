#include <fuzzing/fuzzer.hpp>
#include <fuzzing/gradient_descent.hpp>
#include <fuzzing/iid_node_dependencies.hpp>
#include <utility/timeprof.hpp>

bool fuzzing::path_decision::get_next_direction()
{
    if ( left_max == 0 ) {
        right_current++;
        return true;
    }

    if ( right_max == 0 ) {
        left_current++;
        return false;
    }

    if ( right_max < left_max ) {
        left_current++;
        return false;
    }

    if ( left_max < right_max ) {
        right_current++;
        return true;
    }

    return false;
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

    return branching_direction <=> other.branching_direction;
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
    return node_id.id == other.node_id.id && branching_direction == other.branching_direction;
}


/**
 * @brief Adds a value to the number statistics, updating the minimum, maximum, and mean.
 *
 * This function updates the minimum and maximum values if the provided value is lower or higher,
 * respectively. It also adds the value to the mean calculation.
 *
 * @param value The integer value to be added to the statistics.
 */
void fuzzing::number_statistics::add( int value )
{
    min = std::min( min, value );
    max = std::max( max, value );
    mean.add( value );
}


/**
 * @brief Processes a branching node to update its properties.
 *
 * This function updates the mean depth and direction counts of the given branching node.
 *
 * @param node A pointer to the branching node to be processed.
 */
void fuzzing::coverage_value_props::process_node( branching_node* node )
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
void fuzzing::coverage_value_props::update_mean_depth( branching_node* node )
{
    int node_depth = node->get_depth();
    path_depth.add( node_depth );
}


/**
 * @brief Updates the direction counts for a given branching node.
 *
 * This function calculates the direction counts for the path of the given branching node
 * and updates the minimum and maximum statistics for each direction.
 *
 * @param node A pointer to the branching node for which the direction counts are to be updated.
 */
void fuzzing::coverage_value_props::update_direction_counts( branching_node* node )
{
    std::vector< node_direction > path = get_path( node );

    std::map< node_direction, int > direction_counts;
    for ( const node_direction& nav : path ) {
        direction_counts[ nav ]++;
    }

    for ( auto& [ direction, count ] : direction_counts ) {
        auto& stats = direction_statistics[ direction ];
        stats.add( count );
    }
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
            number_statistics& stats = all_cov_value_props.direction_statistics[ nodes[ i ] ];
            if ( stats.min == stats.max )
                continue;

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

    matrix.clear();
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


std::vector< std::set< fuzzing::node_direction > >
fuzzing::iid_node_dependence_props::get_subsets( std::set< node_direction > const& all_leafs )
{
    std::vector< std::set< node_direction > > subsets;
    std::vector< node_direction > leafs_vector( all_leafs.begin(), all_leafs.end() );
    int n = leafs_vector.size();

    for ( int i = 1; i < ( 1 << n ); ++i ) {
        std::set< node_direction > subset;
        for ( int j = 0; j < n; ++j ) {
            if ( i & ( 1 << j ) ) {
                subset.insert( leafs_vector[ j ] );
            }
        }
        subsets.push_back( subset );
    }

    std::sort( subsets.begin(),
               subsets.end(),
               []( const std::set< node_direction >& a, const std::set< node_direction >& b ) {
                   return a.size() < b.size();
               } );

    return subsets;
}

std::vector< std::vector< float > >
fuzzing::iid_node_dependence_props::get_matrix( std::set< node_direction > const& subset ) const
{
    std::vector< std::vector< float > > sub_matrix;
    for ( const auto& row : matrix ) {
        std::vector< float > sub_row;

        for ( const auto& direction : subset ) {
            int idx = std::distance( interesting_nodes.begin(), interesting_nodes.find( direction ) );
            sub_row.push_back( row[ idx ] );
        }

        sub_matrix.push_back( sub_row );
    }

    return sub_matrix;
}


void fuzzing::iid_node_dependence_props::print_dependencies()
{
    std::cout << "# Dependencies:" << std::endl;
    std::cout << "## Dependencies by loops:" << std::endl;
    for ( const auto& [ loop, nodes ] : dependencies_by_loops ) {
        for ( const auto& body : nodes ) {
            std::cout << "- " << "`(" << body << ") → " << loop.id << "`" << std::endl;
        }
    }

    std::cout << "## Dependencies by sensitivity:" << std::endl;

    std::cout << "## Dependencies by loading:" << std::endl;
    for ( const auto& [ loading, nodes ] : dependencies_by_loading ) {
        for ( const auto& body : nodes ) {
            std::cout << "- " << "`(" << body << ") → " << loading.id << "`" << std::endl;
        }
    }
}

void fuzzing::iid_node_dependence_props::dependencies_generation()
{
    print_dependencies();
    std::set< node_direction > all_leafs;
    for ( const auto& [ _, loop_bodies ] : dependencies_by_loops ) {
        all_leafs.insert( loop_bodies.begin(), loop_bodies.end() );
    }

    std::vector< std::set< node_direction > > subsets = get_subsets( all_leafs );

    std::cout << "# Subsets:" << std::endl;
    for ( const auto& subset : subsets ) {
        std::vector< std::vector< float > > sub_matrix = get_matrix( subset );
        GradientDescent gd( sub_matrix, best_values );
        std::vector< float > weights = gd.optimize();

        std::cout << "## Subset of nodes: `{ ";
        auto delimeter = "";
        for ( const auto& leaf : subset ) {
            std::cout << delimeter << "(" << leaf << ")";
            delimeter = ", ";
        }
        std::cout << " }`" << std::endl;

        for ( size_t i = 0; i < subset.size(); ++i ) {
            const auto& node = *std::next( subset.begin(), i );
            std::cout << "- `(" << node << "): " << weights[ i ] << "`" << std::endl;
        }

        std::cout << "- `Increment: " << weights.back() << "`" << std::endl;
    }

    std::cout << std::endl;
}

std::map< location_id, fuzzing::path_decision > fuzzing::iid_node_dependence_props::generate_path()
{
    dependencies_generation();
    return {};

    std::vector< float > weights = approximate_matrix();

    std::map< fuzzing::node_direction, int > path;
    int path_size = 0;
    int possible_depth = get_possible_depth();

    for ( const auto& [ dir, stats ] : all_cov_value_props.direction_statistics ) {
        if ( stats.min == stats.max ) {
            path[ dir ] = stats.min;
            path_size += stats.min;
        }
    }

    if ( false ) {
        auto it = cov_values_to_props.begin();
        std::cout << "Path Depth" << it->second.path_depth << std::endl;
        std::cout << "Closest value to 0: " << it->first << std::endl;
        for ( const auto& [ direction, stats ] : it->second.direction_statistics ) {
            std::cout << "Direction: " << direction << ", Min: " << stats.min
                      << ", Max: " << stats.max << ", Mean: " << stats.mean << std::endl;
        }
    }

    int computed_size = 0;
    std::map< fuzzing::node_direction, int > computed_path;
    for ( size_t i = 0; i < interesting_nodes.size(); ++i ) {
        const auto& node = *std::next( interesting_nodes.begin(), i );

        auto it = cov_values_to_props.begin();
        int x_1 = it->first;
        int y_1 = it->second.direction_statistics.at( node ).mean;

        ++it;

        int x_2 = it->first;
        int y_2 = it->second.direction_statistics.at( node ).mean;

        int interpolated_y = linear_interpolation( x_1, y_1, x_2, y_2, 0 );
        int computed_count = static_cast< int >( interpolated_y * weights[ i ] );
        computed_count = interpolated_y;
        computed_count = std::max( 0, computed_count );
        computed_size += computed_count;
        computed_path[ node ] = computed_count;
    }

    float scale = static_cast< float >( possible_depth - path_size ) / computed_size;
    for ( auto& [ node, count ] : computed_path ) {
        // std::cout << "Count before scaling: " << count << std::endl;
        count = static_cast< int >( count * scale );
        // std::cout << "Count after scaling: " << count << std::endl;
    }

    path.insert( computed_path.begin(), computed_path.end() );

    std::map< location_id, path_decision > decisions;
    for ( int i = 1; i < path.size(); ++i ) {
        auto first_p = std::next( path.begin(), i - 1 );
        auto second_p = std::next( path.begin(), i );

        if ( first_p->first.node_id == second_p->first.node_id ) {
            decisions[ first_p->first.node_id ] = { first_p->second, second_p->second };
            ++i;
        } else {
            if ( first_p->first.branching_direction ) {
                decisions[ first_p->first.node_id ] = { 0, first_p->second };
            } else {
                decisions[ first_p->first.node_id ] = { first_p->second, 0 };
            }
        }
    }

    if ( false ) {
        for ( const auto& [ location, decision ] : decisions ) {
            std::cout << location.id << decision << std::endl;
        }
    }

    if ( false ) {
        for ( const auto& [ node, count ] : path ) {
            std::cout << "Node ID: " << node.node_id.id << ", Direction: " << node.branching_direction
                      << ", Count: " << count << std::endl;
        }
    }

    return decisions;
}


/**
 * @brief Approximates a matrix using gradient descent optimization.
 *
 * This function utilizes the GradientDescent class to optimize the given matrix
 * and best values, returning a vector of optimized weights.
 *
 * @return A vector of floats representing the optimized weights.
 */
std::vector< float > fuzzing::iid_node_dependence_props::approximate_matrix()
{
    GradientDescent gd( matrix, best_values );
    std::vector< float > weights = gd.optimize();

    if ( false ) {
        for ( size_t i = 0; i < interesting_nodes.size(); ++i ) {
            const auto& node = *std::next( interesting_nodes.begin(), i );
            std::cout << "Node ID: " << node.node_id.id << ", Direction: " << node.branching_direction
                      << ", Weight: " << weights[ i ] << std::endl;
        }
    }

    return weights;
}


/**
 * @brief Computes the possible depth based on the value to mean depth mapping.
 *
 * This function calculates the possible depth by examining the `cov_values_to_props` map.
 * If the map is empty, it returns 0. If the map contains only one element, it returns the mean
 * depth of that element. If the map contains more than one element, it calculates the depth using
 * linear interpolation based on the first two elements in the map.
 *
 * @return The computed possible depth.
 */
int fuzzing::iid_node_dependence_props::get_possible_depth() const
{
    if ( cov_values_to_props.empty() ) {
        return 0;
    }

    if ( cov_values_to_props.size() == 1 ) {
        return cov_values_to_props.begin()->second.path_depth.min;
    }

    auto it = cov_values_to_props.begin();
    int first_depth = it->second.path_depth.min;
    float first_value = it->first;

    ++it;
    int second_depth = it->second.path_depth.min;
    float second_value = it->first;

    int interpolated_depth =
    linear_interpolation( first_value, first_depth, second_value, second_depth, 0 );

    return interpolated_depth;
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

void fuzzing::iid_node_dependence_props::compute_dependencies_by_loading( loading_loops_t& loading_loops,
                                                                          branching_node* end_node )
{
    for ( const auto& bit_index : end_node->sensitive_stdin_bits ) {
        for ( const auto& [ loop_head, values ] : loading_loops ) {
            auto& [ min, max ] = values;

            if ( bit_index >= min && bit_index <= max ) {
                dependencies_by_loading[ loop_head ].insert( { end_node->get_location_id(), true } );
                dependencies_by_loading[ loop_head ].insert( { end_node->get_location_id(), false } );
            }
        }
    }
}

void fuzzing::iid_node_dependence_props::compute_dependencies_by_loading( const loop_to_bodies_t& loop_heads_to_bodies,
                                                                          branching_node* end_node )
{
    branching_node* node = end_node;
    loading_loops_t loading_loops;

    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        loading_loops[ loop_head ] = { std::numeric_limits< natural_32_bit >::max(),
                                       std::numeric_limits< natural_32_bit >::min() };
    }

    while ( node != nullptr ) {
        for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
            if (loop_head.id == node->get_location_id().id) {
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
        for ( const auto& bit_index : node->sensitive_stdin_bits ) {
            for ( const auto& [ loop_head, values ] : loading_loops ) {
                auto& [ min, max ] = values;
                if ( bit_index >= min && bit_index <= max ) {
                    if ( interesting_nodes.contains( { node->get_location_id(), true } ) ) {
                        dependencies_by_loading[ loop_head ].insert( { node->get_location_id(), true } );
                    }

                    if ( interesting_nodes.contains( { node->get_location_id(), false } ) ) {
                        dependencies_by_loading[ loop_head ].insert( { node->get_location_id(), false } );
                    }
                }
            }
        }

        node = node->predecessor;
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
    std::vector< node_direction > path = get_path( node );
    for ( const node_direction& nav : path ) {
        props.interesting_nodes.insert( nav );
    }
    props.recompute_matrix();

    std::unordered_map< location_id, std::unordered_set< location_id > > loop_heads_to_bodies;
    fuzzing::fuzzer::detect_loops_along_path_to_node( node, loop_heads_to_bodies, nullptr );
    props.compute_dependencies_by_loading( loop_heads_to_bodies, node );

    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        for ( const auto& body : loop_bodies ) {
            if ( props.interesting_nodes.contains( { body, true } ) ) {
                props.dependencies_by_loops[ loop_head ].insert( { body, true } );
            }

            if ( props.interesting_nodes.contains( { body, false } ) ) {
                props.dependencies_by_loops[ loop_head ].insert( { body, false } );
            }
        }
    }

    props.cov_values_to_props[ node->best_coverage_value ].process_node( node );
    props.all_cov_value_props.process_node( node );
    props.all_paths.push_back( node );


    // if ( props.update_interesting_nodes( node ) ) {
    //     props.recompute_matrix();
    // } else {
    //     props.add_equation( node );
    // }
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


int fuzzing::linear_interpolation( int x1, int y1, int x2, int y2, int x )
{
    if ( x1 == x2 ) {
        return y1;
    }

    // Perform linear interpolation
    double slope = static_cast< double >( y2 - y1 ) / ( x2 - x1 );
    double y = y1 + slope * ( x - x1 );

    // Round to nearest integer and return
    return static_cast< int >( std::round( y ) );
}