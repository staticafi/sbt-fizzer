#include <fuzzing/fuzzer.hpp>
#include <fuzzing/gradient_descent_with_convergence.hpp>
#include <fuzzing/iid_node_dependencies.hpp>
#include <string>
#include <utility/invariants.hpp>
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
    return get_matrix( std::vector< node_direction >( subset.begin(), subset.end() ) );
}

std::vector< std::vector< float > >
fuzzing::iid_node_dependence_props::get_matrix( std::vector< node_direction > const& subset ) const
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
            std::cout << "- " << "`(" << body << ") → " << loop.first.id << "`" << std::endl;
        }
    }

    std::cout << "## Dependencies by sensitivity:" << std::endl;

    std::cout << "## Dependencies by loading:" << std::endl;
    for ( const auto& [ loading, nodes ] : dependencies_by_loading ) {
        for ( const auto& body : nodes ) {
            std::cout << "- " << "`(" << body << ") → " << loading.id << "`" << std::endl;
        }
    }

    std::cout << "# Subsets:" << std::endl;
}

void fuzzing::iid_node_dependence_props::print_subsets( std::set< node_direction > const& subset,
                                                        GradientDescentResult const& result,
                                                        std::vector< float > const& node_counts )
{
    std::cout << "## Subset of nodes: `{ ";
    auto delimeter = "";
    for ( const auto& leaf : subset ) {
        std::cout << delimeter << "(" << leaf << ")";
        delimeter = ", ";
    }
    std::cout << " }`" << std::endl;

    std::cout << "### Weights and Counts:" << std::endl;
    std::cout << "- `Iterations: " << result.iterations << "`" << std::endl;
    std::cout << "- `Error variance: " << result.error_variance << "`" << std::endl;
    std::cout << "- `Error mean: " << result.error_mean << "`" << std::endl;
    std::cout << "- `Error square of mean: " << result.error_square_of_mean << "`" << std::endl;
    std::cout << "- `Error mean of squares: " << result.error_mean_of_squares << "`" << std::endl;
    std::cout << "- `Variance threshold: " << result.variance_threshold << "`" << std::endl;
    std::cout << "- `Count threshold: " << result.count_threshold << "`" << std::endl;
    std::cout << "- `Converged: " << ( result.converged ? "True" : "False" ) << "`" << std::endl;

    for ( size_t i = 0; i < subset.size(); ++i ) {
        const auto& node = *std::next( subset.begin(), i );
        std::cout << "- `(" << node << "):`" << std::endl;
        std::cout << "    - `Weight: " << result.weights[ i ] << "`" << std::endl;
        std::cout << "    - `Count: " << static_cast< int >( std::round( node_counts[ i ] ) ) << "`" << std::endl;
        std::cout << "    - `Column count weighted: " << result.column_count_weighted[ i ] << "`" << std::endl;
    }

    std::cout << "- `Increment:`\n    - `Weight: " << result.weights.back()
              << "`\n    - `Column count weighted: " << result.column_count_weighted.back() << "`" << std::endl;
}

void fuzzing::iid_node_dependence_props::print_table( std::set< node_direction > const& all_leafs,
                                                      std::vector< TableRow > const& table )
{
    std::unordered_map< std::string, int > headers{
        { "Error mean", 0 },
        { "Error variance", 1 },
        // {"Error square of mean", 2},
        // {"Error mean of squares", 3},
        // {"Variance threshold", 4},
        { "Converged", 5 },
        // { "Iterations", 6 },
        // { "Variance threshold", 7 },
        // { "Count threshold", 8 },
    };

    if ( std::pow( all_leafs.size(), 2 ) - 1 == table.size() ) {
        std::cout << "# Result table:" << std::endl;
    } else {
        std::cout << "# Best result table:" << std::endl;
    }

    std::cout << "| ";
    for ( const auto& node : all_leafs ) {
        std::cout << node << " | ";
    }
    std::cout << "Increment | ";
    for ( const auto& header : headers ) {
        std::cout << header.first << " | ";
    }
    std::cout << std::endl;

    std::cout << "| ";
    for ( size_t i = 0; i <= all_leafs.size() + headers.size(); ++i ) {
        std::cout << "--- | ";
    }
    std::cout << std::endl;

    for ( const auto& row : table ) {
        std::cout << "| ";
        for ( size_t i = 0; i < row.weights.size(); ++i ) {
            const auto& value = row.weights[ i ];
            if ( value.has_value() ) {
                std::cout << value.value();
            }
            std::cout << " | ";
        }

        for ( const auto& header : headers ) {
            int idx = header.second;
            switch ( idx ) {
                case 0: std::cout << row.result.error_mean; break;
                case 1: std::cout << row.result.error_variance; break;
                case 2: std::cout << row.result.error_square_of_mean; break;
                case 3: std::cout << row.result.error_mean_of_squares; break;
                case 4: std::cout << row.result.variance_threshold; break;
                case 5: std::cout << ( row.result.converged ? "True" : "False" ); break;
                case 6: std::cout << row.result.iterations; break;
                case 7: std::cout << row.result.variance_threshold; break;
                case 8: std::cout << row.result.count_threshold; break;
            }
            std::cout << " | ";
        }

        std::cout << std::endl;
    }

    std::cout << std::endl;
}

void fuzzing::iid_node_dependence_props::get_best_subset( std::vector< TableRow > const& table,
                                                          std::vector< std::set< node_direction > > const& subsets,
                                                          std::set< node_direction > const& all_leafs )
{
    std::vector< TableRow > table_copy = table;

    for ( const auto& row_locked : table_copy ) {
        for ( int subset_idx = 0; subset_idx < subsets.size(); ++subset_idx ) {
            auto& row_to_change = table_copy[ subset_idx ];

            if ( row_locked == row_to_change ) {
                continue;
            }

            bool can_be_locked = true;
            for ( size_t i = 0; i < row_locked.weights.size() - 1; ++i ) {
                if ( row_locked.weights[ i ].has_value() && !row_to_change.weights[ i ].has_value() ) {
                    can_be_locked = false;
                    break;
                }
            }

            if ( !can_be_locked ) {
                continue;
            }

            std::set< node_direction > subset = subsets[ subset_idx ];

            std::map< size_t, float > locked_columns;
            int column_idx = 0;
            for ( size_t i = 0; i < row_locked.weights.size() - 1; ++i ) {
                if ( row_locked.weights[ i ].has_value() ) {
                    locked_columns[ column_idx ] = row_locked.weights[ i ].value();
                }

                if ( row_to_change.weights[ i ].has_value() ) {
                    column_idx++;
                }
            }

            GradientDescentNew gd( get_matrix( subset ), best_values, locked_columns );
            auto result = gd.optimize();

            if ( result.error_mean < row_to_change.result.error_mean && result.converged ) {
                std::cout << "- Error was reduced from `" << row_to_change.result.error_mean << "` to `"
                          << result.error_mean
                          << "`, converged: " << ( result.converged ? "`True`" : "`False`" ) << std::endl;

                for ( size_t i = 0; i < all_leafs.size(); ++i ) {
                    const auto& node = *std::next( all_leafs.begin(), i );

                    auto it = std::find( subset.begin(), subset.end(), node );
                    if ( it != subset.end() ) {
                        row_to_change.weights[ i ] = result.weights[ std::distance( subset.begin(), it ) ];
                    } else {
                        row_to_change.weights[ i ] = std::nullopt;
                    }
                }

                row_to_change.result.error_mean = result.error_mean;
                row_to_change.result.converged = row_to_change.result.converged || result.converged;
            }
        }
    }

    std::sort( table_copy.begin(), table_copy.end(), []( const TableRow& a, const TableRow& b ) {
        if ( a.get_non_null_count() != b.get_non_null_count() ) {
            return a.get_non_null_count() < b.get_non_null_count();
        }

        return a.result.error_mean < b.result.error_mean;
    } );

    std::erase_if( table_copy, [ & ]( const TableRow& row ) {
        return !row.result.converged && row.get_non_null_count() != all_leafs.size() + 1;
    } );

    print_table( all_leafs, table_copy );
}

void fuzzing::iid_node_dependence_props::dependencies_generation()
{
    print_dependencies();
    std::set< node_direction > all_leafs;
    for ( const auto& [ _, loop_bodies ] : dependencies_by_loops ) {
        all_leafs.insert( loop_bodies.begin(), loop_bodies.end() );
    }

    std::vector< std::set< node_direction > > subsets = get_subsets( all_leafs );

    std::vector< TableRow > table;


    for ( const auto& subset : subsets ) {
        std::vector< std::vector< float > > sub_matrix = get_matrix( subset );

        GradientDescentNew gd( sub_matrix, best_values );
        auto result = gd.optimize();

        std::vector< float > const& weights = result.weights;

        float dot_product = std::inner_product( weights.begin(), weights.end() - 1, weights.begin(), 0.0f );
        std::vector< float > node_counts;
        for ( auto it = weights.begin(); it != weights.end() - 1; ++it ) {
            node_counts.push_back( -weights.back() * ( *it ) / dot_product );
        }

        std::vector< std::optional< float > > weights_with_nulls;
        for ( const auto& node : all_leafs ) {
            auto it = std::find( subset.begin(), subset.end(), node );
            if ( it != subset.end() ) {
                weights_with_nulls.push_back( weights[ std::distance( subset.begin(), it ) ] );
            } else {
                weights_with_nulls.push_back( std::nullopt );
            }
        }

        weights_with_nulls.push_back( weights.back() );
        TableRow row( weights_with_nulls, result );

        table.push_back( row );

        print_subsets( subset, result, node_counts );
        gd.print_input_matrix();
    }

    print_table( all_leafs, table );
    get_best_subset( table, subsets, all_leafs );
}

std::vector< fuzzing::node_direction > fuzzing::iid_node_dependence_props::get_all_leafs()
{
    std::set< node_direction > all_leafs;
    for ( const auto& [ _, loop_bodies ] : dependencies_by_loops ) {
        all_leafs.insert( loop_bodies.begin(), loop_bodies.end() );
    }

    return std::vector< node_direction >( all_leafs.begin(), all_leafs.end() );
}

std::tuple< std::vector< std::vector< float > >, std::vector< float > >
fuzzing::iid_node_dependence_props::get_unique_matrix_and_values( std::vector< std::vector< float > > const& full_matrix )
{
    std::set< std::vector< float > > unique_rows;
    std::vector< float > new_best_values;
    std::vector< std::vector< float > > matrix;

    for ( size_t i = 0; i < full_matrix.size(); ++i ) {
        auto row = full_matrix[ i ];
        row.push_back( best_values[ i ] );

        if ( unique_rows.insert( row ).second ) {
            new_best_values.push_back( best_values[ i ] );
            matrix.push_back( full_matrix[ i ] );
        }
    }

    return { matrix, new_best_values };
}

std::set< DirectionVector > fuzzing::iid_node_dependence_props::vector_computation()
{
    std::vector< fuzzing::node_direction > all_leafs = get_all_leafs();
    std::vector< std::vector< float > > full_matrix = get_matrix( all_leafs );
    auto [ matrix, new_best_values ] = get_unique_matrix_and_values( full_matrix );

    std::set< DirectionVector > vectors_with_hits;

    auto is_approximately_equal = []( const auto& a, const auto& b ) {
        constexpr float epsilon = 1e-6;
        return a.size() == b.size() && std::equal( a.begin(), a.end(), b.begin(), [ epsilon ]( float x, float y ) {
                   return std::fabs( x - y ) <= epsilon;
               } );
    };

    for ( size_t i = 0; i < matrix.size(); ++i ) {
        for ( size_t j = 0; j < matrix.size(); ++j ) {
            if ( i == j )
                continue;

            std::vector< float > diff_vector;
            std::transform( matrix[ i ].begin(),
                            matrix[ i ].end(),
                            matrix[ j ].begin(),
                            std::back_inserter( diff_vector ),
                            std::minus<>() );

            if ( std::any_of( diff_vector.begin(), diff_vector.end(), []( float val ) { return val < 0; } ) )
                continue;

            float best_value_diff = new_best_values[ i ] - new_best_values[ j ];
            if ( best_value_diff != 0 ) {
                int compare_hits = 0;

                for ( const auto& row : matrix ) {
                    std::vector< float > new_row( row.size() );
                    std::transform( row.begin(), row.end(), diff_vector.begin(), new_row.begin(), std::plus<>() );

                    if ( std::any_of( matrix.begin(), matrix.end(), [ & ]( const auto& existing_row ) {
                             return is_approximately_equal( new_row, existing_row );
                         } ) ) {
                        compare_hits++;
                    }
                }

                vectors_with_hits.insert( { diff_vector, best_value_diff, compare_hits } );
            }
        }
    }

    // std::cout << "Vectors:\n";
    // for ( const auto& vec : vectors_with_hits ) {
    //     std::cout << "( ";
    //     for ( size_t i = 0; i < vec.vector.size(); ++i ) {
    //         std::cout << ( i ? ", " : "" ) << vec.vector[ i ];
    //     }
    //     std::cout << " ) -> " << vec.value << " (" << vec.compare_hits << ")\n";
    // }

    return vectors_with_hits;
}

std::unordered_map< location_id::id_type, float > fuzzing::iid_node_dependence_props::generate_probabilities()
{
    // dependencies_generation();
    std::vector< node_direction > all_leafs = get_all_leafs();
    auto [ matrix, new_best_values ] = get_unique_matrix_and_values( get_matrix( all_leafs ) );
    std::set< DirectionVector > vectors = vector_computation();

    float epsilon = 1e-6;
    int column_count = matrix[ 0 ].size();

    std::set< std::vector< float > > paths;
    // std::cout << "Path counts:" << std::endl;
    for ( const auto& vec : vectors ) {

        for ( int i = 0; i < matrix.size(); ++i ) {
            std::vector< float > path_counts( column_count );

            float curr_best_value = std::abs( new_best_values[ i ] );

            float counts = curr_best_value / vec.value;
            int counts_int = static_cast< int >( std::round( counts ) );
            if ( std::abs( counts - counts_int ) > epsilon ) {
                continue;
            }

            for ( int j = 0; j < column_count; ++j ) {
                path_counts[ j ] = matrix[ i ][ j ] + vec.vector[ j ] * counts_int;
            }

            if ( std::any_of( path_counts.begin(), path_counts.end(), []( float val ) { return val < 0; } ) ) {
                continue;
            }

            // std::cout << "( ";
            // for ( size_t j = 0; j < column_count; ++j ) {
            //     std::cout << ( j ? ", " : "" ) << path_counts[ j ];
            // }
            // std::cout << " ) " << std::endl;


            paths.insert( path_counts );
        }
    }

    std::vector< std::vector< float > > sorted_paths( paths.begin(), paths.end() );
    std::sort( sorted_paths.begin(),
               sorted_paths.end(),
               []( const std::vector< float >& a, const std::vector< float >& b ) {
                   float a_length = std::inner_product( a.begin(), a.end(), a.begin(), 0.0f );
                   float b_length = std::inner_product( b.begin(), b.end(), b.begin(), 0.0f );
                   return a_length < b_length;
               } );

    // for ( const auto& path : sorted_paths ) {
    //     std::cout << "( ";
    //     for ( size_t i = 0; i < path.size(); ++i ) {
    //         std::cout << ( i ? ", " : "" ) << path[ i ];
    //     }
    //     std::cout << " )" << std::endl;
    // }

    std::map< location_id::id_type, std::pair< float, float > > path_counts = compute_counts_from_leaf_counts( sorted_paths[ 0 ], all_leafs );
    for (const auto& [id, counts] : path_counts) {
        std::cout << "Location ID: " << id << ", Left Count: " << counts.first << ", Right Count: " << counts.second << std::endl;
    }

    std::unordered_map< location_id::id_type, float > path_probabilities;
    for ( int i = 0; i < path_counts.size(); i += 2 ) {}

    // for ( int i = 0; i < all_leafs.size(); i += 2 ) {
    //     int sum = sorted_paths[ 0 ][ i ] + sorted_paths[ 0 ][ i + 1 ];
    //     location_id::id_type id = std::next( all_leafs.begin(), i )->node_id.id;
    //     if ( sum > 0 )
    //         path_probabilities[ id ] = sorted_paths[ 0 ][ i ] / sum;
    // }

    // for (const auto& [id, count] : path_probabilities) {
    //     std::cout << "Location ID: " << id << ", Path Probability: " << count << std::endl;
    // }

    return path_probabilities;
    return {};
}

std::map< location_id::id_type, std::pair< float, float > >
fuzzing::iid_node_dependence_props::compute_counts_from_leaf_counts( std::vector< float > const& leaf_counts,
                                                                     std::vector< node_direction > all_leafs )
{
    std::map< location_id::id_type, std::pair< float, float > > path_counts;
    for ( int i = 0; i < all_leafs.size(); i += 2 ) {
        float leaf_count = leaf_counts[ i ];
        node_direction leaf = all_leafs[ i ];

        auto& [ left_count, right_count ] = path_counts[ leaf.node_id.id ];
        if ( leaf.branching_direction ) {
            right_count = leaf_count;
        } else {
            left_count = leaf_count;
        }
    }

    for ( const auto& [ loop_head, dependent_bodies ] : dependencies_by_loops ) {
        float loop_count = 0;
        for ( const auto& body : dependent_bodies ) {
            auto& [ left_count, right_count ] = path_counts[ body.node_id.id ];
            loop_count += right_count;
            loop_count += left_count;
        }

        location_id head_id = loop_head.first;
        bool end_direction = loop_head.second;

        if ( end_direction ) {
            path_counts[ head_id.id ] = { 1, loop_count };
        } else {
            path_counts[ head_id.id ] = { loop_count, 1 };
        }
    }

    return path_counts;
}


std::map< location_id, fuzzing::path_decision > fuzzing::iid_node_dependence_props::generate_path()
{
    // // dependencies_generation();
    // std::vector< node_direction > all_leafs = get_all_leafs();
    // auto [ matrix, new_best_values ] = get_unique_matrix_and_values( get_matrix( all_leafs ) );
    // std::set< DirectionVector > vectors = vector_computation();

    // // auto min_value_it = std::min_element( best_values.begin(), best_values.end() );
    // // int min_index = std::distance( best_values.begin(), min_value_it );
    // // std::vector< float > min_row = matrix[ min_index ];

    // float epsilon = 1e-6;
    // int column_count = matrix[ 0 ].size();

    // std::set< std::vector< float > > paths;
    // std::cout << "Path counts:" << std::endl;
    // for ( const auto& vec : vectors ) {

    //     for ( int i = 0; i < matrix.size(); ++i ) {
    //         std::vector< float > path_counts( column_count );

    //         float curr_best_value = std::abs( new_best_values[ i ] );

    //         float counts = curr_best_value / vec.value;
    //         int counts_int = static_cast< int >( std::round( counts ) );
    //         if ( std::abs( counts - counts_int ) > epsilon ) {
    //             continue;
    //         }

    //         for ( int j = 0; j < column_count; ++j ) {
    //             path_counts[ j ] = matrix[ i ][ j ] + vec.vector[ j ] * counts_int;
    //         }

    //         if ( std::any_of( path_counts.begin(), path_counts.end(), []( float val ) { return val < 0; } ) ) {
    //             continue;
    //         }

    //         // std::cout << "( ";
    //         // for ( size_t j = 0; j < column_count; ++j ) {
    //         //     std::cout << ( j ? ", " : "" ) << path_counts[ j ];
    //         // }
    //         // std::cout << " ) " << std::endl;


    //         paths.insert( path_counts );
    //     }
    // }

    // std::vector< std::vector< float > > sorted_paths( paths.begin(), paths.end() );
    // std::sort( sorted_paths.begin(),
    //            sorted_paths.end(),
    //            []( const std::vector< float >& a, const std::vector< float >& b ) {
    //                float a_length = std::inner_product( a.begin(), a.end(), a.begin(), 0.0f );
    //                float b_length = std::inner_product( b.begin(), b.end(), b.begin(), 0.0f );
    //                return a_length < b_length;
    //            } );

    // // for ( const auto& path : sorted_paths ) {
    // //     std::cout << "( ";
    // //     for ( size_t i = 0; i < path.size(); ++i ) {
    // //         std::cout << ( i ? ", " : "" ) << path[ i ];
    // //     }
    // //     std::cout << " )" << std::endl;
    // // }

    // std::unordered_map< location_id::id_type, float > path_counts;
    // INVARIANT( all_leafs.size() % 2 == 0 );

    // for ( int i = 0; i < all_leafs.size(); i += 2 ) {
    //     int sum = sorted_paths[ 0 ][ i ] + sorted_paths[ 0 ][ i + 1 ];
    //     location_id::id_type id = std::next( all_leafs.begin(), i )->node_id.id;
    //     if ( sum > 0 )
    //         path_counts[ id ] = sorted_paths[ 0 ][ i ] / sum;
    //     else
    //         path_counts[ id ] = 0.5;
    // }

    // for ( const auto& [ id, count ] : path_counts ) {
    //     std::cout << "Location ID: " << id << ", Path Count: " << count << std::endl;
    // }
    return {};
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
    GradientDescentNew gd( matrix, best_values );
    GradientDescentResult result = gd.optimize();

    if ( false ) {
        for ( size_t i = 0; i < interesting_nodes.size(); ++i ) {
            const auto& node = *std::next( interesting_nodes.begin(), i );
            std::cout << "Node ID: " << node.node_id.id << ", Direction: " << node.branching_direction
                      << ", Weight: " << result.weights[ i ] << std::endl;
        }
    }

    return result.weights;
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

    int interpolated_depth = linear_interpolation( first_value, first_depth, second_value, second_depth, 0 );

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

    std::map< location_id, bool > loop_heads_ending;
    branching_node* current = node;
    while ( current != nullptr ) {
        branching_node* predecessor = current->predecessor;
        if ( predecessor != nullptr && loop_heads_to_bodies.contains( predecessor->get_location_id() ) &&
             !loop_heads_ending.contains( predecessor->get_location_id() ) ) {
            bool direction = predecessor->successor( true ).pointer->get_location_id() ==
                             current->get_location_id();
            loop_heads_ending[ predecessor->get_location_id() ] = direction;
        }
        current = predecessor;
    }

    for ( const auto& [ loop_head, loop_bodies ] : loop_heads_to_bodies ) {
        INVARIANT( loop_heads_ending.contains( loop_head ) );
        bool loop_head_direction = loop_heads_ending[ loop_head ];

        for ( const auto& body : loop_bodies ) {
            if ( props.interesting_nodes.contains( { body, true } ) ) {
                props.dependencies_by_loops[ { loop_head, loop_head_direction } ].insert( { body, true } );
            }

            if ( props.interesting_nodes.contains( { body, false } ) ) {
                props.dependencies_by_loops[ { loop_head, loop_head_direction } ].insert( { body, false } );
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
            node_direction nav = { predecessor->get_location_id(), predecessor->successor_direction( current ) };
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