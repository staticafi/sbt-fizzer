#include <algorithm>
#include <cmath>
#include <fuzzing/gradient_descent.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <iostream>
#include <stdexcept>
#include <random>

GradientDescent::GradientDescent( float learning_rate, int max_iterations, float convergence_threshold )
    : _learning_rate( learning_rate )
    , _max_iterations( max_iterations )
    , _convergence_threshold( convergence_threshold )
{}

std::vector< float > GradientDescent::optimize( const std::vector< std::vector< float > >& coefficient_matrix,
                                                const std::vector< float >& target_vector )
{
    TMPROF_BLOCK();

    if ( coefficient_matrix.empty() || target_vector.empty() ||
         coefficient_matrix.size() != target_vector.size() ) {
        throw std::invalid_argument( "Invalid input dimensions" );
    }

    std::vector< float > current_solution = generateRandomWeights( coefficient_matrix[ 0 ].size() );

    std::vector< float > gradient;
    float prev_cost = std::numeric_limits< float >::max();

    for ( int iteration = 0; iteration < _max_iterations; ++iteration ) {
        gradient = computeGradient( current_solution, coefficient_matrix, target_vector );

        // Update current_solution
        for ( size_t i = 0; i < current_solution.size(); ++i ) {
            current_solution[ i ] -= _learning_rate * gradient[ i ];
        }

        // Check for convergence
        float current_cost =
        computeMeanSquaredError( current_solution, coefficient_matrix, target_vector );

        // Debug output
        if ( _debug && iteration % 50 == 0 ) {
            std::cout << "Iteration " << iteration << ", Cost: " << current_cost << std::endl;
        }

        if ( std::abs( current_cost - prev_cost ) < _convergence_threshold ) {
            std::cout << "Converged after " << iteration << " iterations." << std::endl;
            std::cout << "Number of equations: " << coefficient_matrix.size() << std::endl;
            break;
        }
        prev_cost = current_cost;
    }

    normalize( current_solution, 0.0f, 100.0f );
    return current_solution;
}

std::vector< float > GradientDescent::computeGradient( const std::vector< float >& current_solution,
                                                       const std::vector< std::vector< float > >& coefficient_matrix,
                                                       const std::vector< float >& target_vector )
{
    std::vector< float > gradient( current_solution.size(), 0.0f );

    for ( size_t i = 0; i < coefficient_matrix.size(); ++i ) {
        float predicted = dotProduct( current_solution, coefficient_matrix[ i ] );
        float error = predicted - target_vector[ i ];

        for ( size_t j = 0; j < current_solution.size(); ++j ) {
            gradient[ j ] += 2 * error * coefficient_matrix[ i ][ j ];
        }
    }

    for ( float& grad : gradient ) {
        grad /= coefficient_matrix.size();
    }

    return gradient;
}

float GradientDescent::computeMeanSquaredError( const std::vector< float >& current_solution,
                                                const std::vector< std::vector< float > >& coefficient_matrix,
                                                const std::vector< float >& target_vector )
{
    float mse = 0.0f;

    for ( size_t i = 0; i < coefficient_matrix.size(); ++i ) {
        float predicted = dotProduct( current_solution, coefficient_matrix[ i ] );
        float error = predicted - target_vector[ i ];
        mse += error * error;
    }

    return mse / coefficient_matrix.size();
}

float GradientDescent::dotProduct( const std::vector< float >& a, const std::vector< float >& b )
{
    INVARIANT( a.size() == b.size() );

    float result = 0.0f;
    for ( size_t i = 0; i < a.size(); ++i ) {
        result += a[ i ] * b[ i ];
    }
    return result;
}

std::vector< float > GradientDescent::generateRandomWeights( size_t n )
{
    std::vector< float > weights( n );
    std::random_device rd;
    std::mt19937 gen( rd() );
    std::normal_distribution<> d( 0, 1.0 / std::sqrt( n ) );
    for ( auto& weight : weights ) {
        weight = d( gen );
    }

    return weights;
}

std::vector< float > GradientDescent::normalize( std::vector< float >& values,
                                                 float min_value,
                                                 float max_value )
{
    if (values.empty()) {
        return values;
    }

    float min_elem = *std::min_element(values.begin(), values.end());
    float max_elem = *std::max_element(values.begin(), values.end());

    if (min_elem != max_elem) {
        for (auto& value : values) {
            value = min_value + (value - min_elem) * (max_value - min_value) / (max_elem - min_elem);
        }
    }

    return values;
}