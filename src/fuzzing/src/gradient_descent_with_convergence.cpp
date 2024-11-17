#include <algorithm>
#include <cmath>
#include <fuzzing/gradient_descent_with_convergence.hpp>
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <stdexcept>
#include <vector>

GradientDescentNew::GradientDescentNew( const std::vector< std::vector< float > >& coefficient_matrix,
                                        const std::vector< float >& target_vector,
                                        float learning_rate,
                                        int max_iterations,
                                        float convergence_threshold,
                                        float momentum )
    : _coefficient_matrix( coefficient_matrix )
    , _target_vector( target_vector )
    , _learning_rate( learning_rate )
    , _max_iterations( max_iterations )
    , _convergence_threshold( convergence_threshold )
    , _momentum( momentum )
{
    std::set< std::vector< float > > unique_rows;
    std::vector< float > new_target_vector;
    std::vector< std::vector< float > > new_coefficient_matrix;

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        std::vector< float > row = _coefficient_matrix[ i ];
        row.push_back( _target_vector[ i ] );

        if ( unique_rows.insert( row ).second ) {
            new_target_vector.push_back( _target_vector[ i ] );
            new_coefficient_matrix.push_back( _coefficient_matrix[ i ] );
        }
    }

    _coefficient_matrix = new_coefficient_matrix;
    _target_vector = new_target_vector;

    if ( _coefficient_matrix.empty() || _target_vector.empty() ||
         _coefficient_matrix.size() != _target_vector.size() ) {
        throw std::invalid_argument( "Invalid input dimensions" );
    }

    for ( auto& row : _coefficient_matrix ) {
        row.push_back( 1.0f );
    }
}

void GradientDescentNew::print_input_matrix()
{
    std::cout << "### Equation Matrix:" << std::endl;
    std::cout << "$$\\begin{bmatrix}" << std::endl;
    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        for ( size_t j = 0; j < _coefficient_matrix[ i ].size(); ++j ) {
            std::cout << _coefficient_matrix[ i ][ j ];
            if ( j < _coefficient_matrix[ i ].size() - 1 ) {
                std::cout << " & ";
            }
        }
        std::cout << " & " << _target_vector[ i ];
        if ( i < _coefficient_matrix.size() - 1 ) {
            std::cout << " \\\\";
        }
        std::cout << std::endl;
    }
    std::cout << "\\end{bmatrix}$$" << std::endl;
}

GradientDescentResult GradientDescentNew::optimize()
{
    std::vector< float > current_solution = generate_random_weights( _coefficient_matrix[ 0 ].size() );
    std::vector< float > prev_errors = compute_errors( current_solution );
    std::vector< float > velocity( current_solution.size(), 0.0f );
    float prev_cost = std::numeric_limits< float >::max();
    bool converged = false;
    int iterations = 0;

    for ( ; iterations < _max_iterations; ++iterations ) {
        std::vector< float > gradient = compute_gradient( current_solution );

        for ( size_t i = 0; i < current_solution.size(); ++i ) {
            velocity[ i ] = _momentum * velocity[ i ] - _learning_rate * gradient[ i ];
            current_solution[ i ] += velocity[ i ];
        }

        std::vector< float > errors = compute_errors( current_solution );
        float current_cost = compute_mean_squared_error( errors );

        if ( std::abs( current_cost - prev_cost ) < _convergence_threshold ) {
            break;
        }

        prev_cost = current_cost;
        prev_errors = errors;
    }

    float error_variance = compute_variance( prev_errors );
    float error_mean = compute_mean( prev_errors );
    std::vector< float > counts_per_column = compute_column_count( current_solution );

    float variance_threshold = 0.0f;
    float count_threshold = 0.0f;

    converged =
    compute_convergence( counts_per_column, error_variance, error_mean, variance_threshold, count_threshold );

    return GradientDescentResult{ .weights = current_solution,
                                  .errors = prev_errors,
                                  .column_count_weighted = counts_per_column,
                                  .iterations = iterations,
                                  .error_mean = error_mean,
                                  .error_square_of_mean = float( std::pow( error_mean, 2 ) ),
                                  .error_mean_of_squares = prev_cost,
                                  .error_variance = error_variance,
                                  .variance_threshold = variance_threshold,
                                  .count_threshold = count_threshold,
                                  .converged = converged };
}

std::vector< float > GradientDescentNew::compute_column_count( const std::vector< float >& current_solution )
{
    std::vector< float > counts_per_column( current_solution.size(), 0.0f );

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        for ( size_t j = 0; j < _coefficient_matrix[ i ].size(); ++j ) {
            counts_per_column[ j ] += std::abs( _coefficient_matrix[ i ][ j ] * current_solution[ j ] );
        }
    }

    return counts_per_column;
}

bool GradientDescentNew::compute_convergence( const std::vector< float >& counts_per_column,
                                              float error_variance,
                                              float error_mean,
                                              float& variance_threshold,
                                              float& count_threshold )
{
    constexpr float VARIANCE_SCALING_FACTOR = 10.0f;

    variance_threshold = std::abs( error_mean * VARIANCE_SCALING_FACTOR );

    float column_count_sum = std::abs(
    std::accumulate( counts_per_column.begin(), counts_per_column.end() - 1, 0.0f ) );
    count_threshold = column_count_sum * 0.01f;

    if ( error_variance > variance_threshold  ) {
        return false;
    }

    for ( size_t i = 0; i < counts_per_column.size() - 1; ++i ) {
        if ( std::abs( counts_per_column[ i ] ) < count_threshold ) {
            return false;
        }
    }

    return true;
}

std::vector< float > GradientDescentNew::compute_gradient( const std::vector< float >& current_solution )
{
    std::vector< float > gradient( current_solution.size(), 0.0f );

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        float predicted = dot_product( current_solution, _coefficient_matrix[ i ] );
        float error = predicted - _target_vector[ i ];

        for ( size_t j = 0; j < current_solution.size(); ++j ) {
            gradient[ j ] += 2 * error * _coefficient_matrix[ i ][ j ];
        }
    }

    for ( float& grad : gradient ) {
        grad /= _coefficient_matrix.size();
    }

    return gradient;
}

std::vector< float > GradientDescentNew::compute_errors( const std::vector< float >& current_solution )
{
    std::vector< float > errors( _coefficient_matrix.size(), 0.0f );

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        float predicted = dot_product( current_solution, _coefficient_matrix[ i ] );
        errors[ i ] = predicted - _target_vector[ i ];
    }

    return errors;
}

float GradientDescentNew::compute_mean_squared_error( const std::vector< float >& errors )
{
    float mse = 0.0f;

    for ( size_t i = 0; i < errors.size(); ++i ) {
        mse += std::pow( errors[ i ], 2 );
    }

    return mse / errors.size();
}

float GradientDescentNew::dot_product( const std::vector< float >& a, const std::vector< float >& b )
{
    if ( a.size() != b.size() ) {
        throw std::invalid_argument( "Vectors must have the same size for dot product" );
    }

    return std::inner_product( a.begin(), a.end(), b.begin(), 0.0f );
}

std::vector< float > GradientDescentNew::generate_random_weights( size_t n )
{
    std::vector< float > weights( n );
    std::random_device rd;
    std::mt19937 gen( rd() );
    std::uniform_real_distribution<> d( -0.01, 0.01 );

    std::generate( weights.begin(), weights.end(), [ & ]() { return d( gen ); } );

    return weights;
}


float GradientDescentNew::compute_variance( const std::vector< float >& errors )
{
    float mean = compute_mean( errors );
    float error_variance = 0.0f;

    for ( const auto& error : errors ) {
        error_variance += std::pow( error - mean, 2 );
    }

    return error_variance / errors.size();
}

float GradientDescentNew::compute_mean( const std::vector< float >& errors )
{
    return std::accumulate( errors.begin(), errors.end(), 0.0f ) / errors.size();
}