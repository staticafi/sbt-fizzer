#include <algorithm>
#include <cmath>
#include <fuzzing/gradient_descent.hpp>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>

/**
 * @brief Constructs a GradientDescent object.
 *
 * @param coefficient_matrix The matrix of coefficients for the linear system.
 * @param target_vector The target vector for the linear system.
 * @param learning_rate The learning rate for gradient descent (default: 0.001).
 * @param max_iterations The maximum number of iterations (default: 10000).
 * @param convergence_threshold The threshold for convergence (default: 1e-6).
 * @throws std::invalid_argument if input dimensions are invalid.
 */
GradientDescent::GradientDescent( const std::vector< std::vector< float > >& coefficient_matrix,
                                  const std::vector< float >& target_vector,
                                  float learning_rate,
                                  int max_iterations,
                                  float convergence_threshold )
    : _coefficient_matrix( coefficient_matrix )
    , _target_vector( target_vector )
    , _learning_rate( learning_rate )
    , _max_iterations( max_iterations )
    , _convergence_threshold( convergence_threshold )
{
    if ( coefficient_matrix.empty() || target_vector.empty() ||
         coefficient_matrix.size() != target_vector.size() ) {
        throw std::invalid_argument( "Invalid input dimensions" );
    }
}

/**
 * @brief Performs gradient descent optimization.
 *
 * @return std::vector<float> The optimized solution vector.
 */
std::vector< float > GradientDescent::optimize()
{
    std::vector< float > current_solution = generateRandomWeights( _coefficient_matrix[ 0 ].size() );

    float prev_cost = std::numeric_limits< float >::max();

    for ( int iteration = 0; iteration < _max_iterations; ++iteration ) {
        std::vector< float > gradient = computeGradient( current_solution );

        // Update current_solution
        for ( size_t i = 0; i < current_solution.size(); ++i ) {
            current_solution[ i ] -= _learning_rate * gradient[ i ];
        }

        // Check for convergence
        float current_cost = computeMeanSquaredError( current_solution );

        // Debug output
        if ( _debug && iteration % 100 == 0 ) {
            std::cout << "Iteration " << iteration << ", Cost: " << current_cost << std::endl;
            std::cout << "Gradient: [ ";
            for ( const auto& val : gradient ) {
                std::cout << val << " ";
            }
            std::cout << "]" << std::endl;
        }

        if ( std::abs( current_cost - prev_cost ) < _convergence_threshold ) {
            std::cout << "Converged after " << iteration << " iterations." << std::endl;
            std::cout << "Number of equations: " << _coefficient_matrix.size() << std::endl;
            break;
        }
        prev_cost = current_cost;
    }

    rescale( current_solution, -1.0f, 1.0f );
    return current_solution;
}

/**
 * @brief Computes the gradient for the current solution.
 *
 * @param current_solution The current solution vector.
 * @return std::vector<float> The computed gradient vector.
 */
std::vector< float > GradientDescent::computeGradient( const std::vector< float >& current_solution )
{
    std::vector< float > gradient( current_solution.size(), 0.0f );

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        float predicted = dotProduct( current_solution, _coefficient_matrix[ i ] );
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

/**
 * @brief Computes the mean squared error for the current solution.
 *
 * @param current_solution The current solution vector.
 * @return float The computed mean squared error.
 */
float GradientDescent::computeMeanSquaredError( const std::vector< float >& current_solution )
{
    float mse = 0.0f;

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        float predicted = dotProduct( current_solution, _coefficient_matrix[ i ] );
        float error = predicted - _target_vector[ i ];
        mse += error * error;
    }

    return mse / _coefficient_matrix.size();
}

/**
 * @brief Computes the dot product of two vectors.
 *
 * @param a The first vector.
 * @param b The second vector.
 * @return float The dot product of the two vectors.
 * @throws std::invalid_argument if the vectors have different sizes.
 */
float GradientDescent::dotProduct( const std::vector< float >& a, const std::vector< float >& b )
{
    if ( a.size() != b.size() ) {
        throw std::invalid_argument( "Vectors must have the same size for dot product" );
    }

    return std::inner_product( a.begin(), a.end(), b.begin(), 0.0f );
}

/**
 * @brief Generates a vector of random weights.
 *
 * @param n The size of the weight vector to generate.
 * @return std::vector<float> A vector of random weights.
 */
std::vector< float > GradientDescent::generateRandomWeights( size_t n )
{
    std::vector< float > weights( n );
    std::random_device rd;
    std::mt19937 gen( rd() );
    std::normal_distribution<> d( 0, 1.0 / std::sqrt( n ) );

    std::generate( weights.begin(), weights.end(), [ & ]() { return d( gen ); } );

    return weights;
}

/**
 * @brief Rescales the values in a vector to a specified range.
 *
 * @param values The vector of values to rescale.
 * @param min_value The minimum value of the new range.
 * @param max_value The maximum value of the new range.
 */
void GradientDescent::rescale( std::vector< float >& values, float min_value, float max_value )
{
    if ( values.empty() ) {
        return;
    }

    auto [ min_elem, max_elem ] = std::minmax_element( values.begin(), values.end() );

    if ( *min_elem != *max_elem ) {
        std::transform( values.begin(), values.end(), values.begin(), [ & ]( float value ) {
            return min_value +
                   ( value - *min_elem ) * ( max_value - min_value ) / ( *max_elem - *min_elem );
        } );
    }
}