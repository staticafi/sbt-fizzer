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
 * @param momentum The momentum factor for gradient descent (default: 0.9).
 * @throws `std::invalid_argument` if input dimensions are invalid.
 */
GradientDescent::GradientDescent( std::vector< std::vector< float > >& coefficient_matrix,
                                  std::vector< float >& target_vector,
                                  float learning_rate,
                                  int max_iterations,
                                  float convergence_threshold,
                                  float momentum )
    : _coefficient_matrix( coefficient_matrix )
    , _target_vector( target_vector )
    , _learning_rate( learning_rate )
    , _max_iterations( max_iterations )
    , _convergence_threshold( convergence_threshold )
    , _momentum(momentum)
{
    if ( coefficient_matrix.empty() || target_vector.empty() ||
         coefficient_matrix.size() != target_vector.size() ) {
        throw std::invalid_argument( "Invalid input dimensions" );
    }
}

/**
 * @brief Performs gradient descent optimization with momentum.
 *
 * @return std::vector<float> The optimized solution vector.
 */
std::vector< float > GradientDescent::optimize()
{
    min_max_normalize(_coefficient_matrix);
    min_max_normalize_target(_target_vector);

    if (_debug) {
        std::cout << "Coefficient Matrix and Target Vector:" << std::endl;
        for (size_t i = 0; i < _coefficient_matrix.size(); ++i) {
            for (const auto& val : _coefficient_matrix[i]) {
            std::cout << val << " ";
            }
            std::cout << "| " << _target_vector[i] << std::endl;
        }
    }

    std::vector< float > current_solution = generate_random_weights( _coefficient_matrix[ 0 ].size() );
    std::vector< float > velocity(current_solution.size(), 0.0f); // Initialize velocity to 0

    float prev_cost = std::numeric_limits< float >::max();

    for ( int iteration = 0; iteration < _max_iterations; ++iteration ) {
        std::vector< float > gradient = compute_gradient( current_solution );

        // Update current_solution with momentum
        for ( size_t i = 0; i < current_solution.size(); ++i ) {
            velocity[i] = _momentum * velocity[i] - _learning_rate * gradient[i];
            current_solution[i] += velocity[i];  // Update with velocity
        }

        // Check for convergence
        float current_cost = compute_mean_squared_error( current_solution );

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

    // add_smallest_value( current_solution );
    rescale( current_solution, 0.0f, 1.0f );
    return current_solution;
}



/**
 * @brief Computes the gradient for the current solution.
 *
 * @param current_solution The current solution vector.
 * @return std::vector<float> The computed gradient vector.
 */
std::vector< float > GradientDescent::compute_gradient( const std::vector< float >& current_solution )
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

/**
 * @brief Computes the mean squared error for the current solution.
 *
 * @param current_solution The current solution vector.
 * @return float The computed mean squared error.
 */
float GradientDescent::compute_mean_squared_error( const std::vector< float >& current_solution )
{
    float mse = 0.0f;

    for ( size_t i = 0; i < _coefficient_matrix.size(); ++i ) {
        float predicted = dot_product( current_solution, _coefficient_matrix[ i ] );
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
float GradientDescent::dot_product( const std::vector< float >& a, const std::vector< float >& b )
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
std::vector< float > GradientDescent::generate_random_weights( size_t n )
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
    for ( float& value : values ) {
        std::cout << value << std::endl;
    }

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

    std::cout << std::endl;

    for ( float& value : values ) {
        std::cout << value << std::endl;
    }
    std::cout << std::endl;
    std::cout << std::endl;
}

/**
 * @brief Adds the smallest value in the vector to each element of the vector.
 *
 * This function finds the smallest value in the given vector and adds its absolute value
 * to each element of the vector. If the vector is empty, the function does nothing.
 *
 * @param values A reference to a vector of floats to be modified.
 */
void GradientDescent::add_smallest_value( std::vector< float >& values )
{
    auto min_elem = std::min_element( values.begin(), values.end() );

    if ( min_elem != values.end() ) {
        float min_value = *min_elem;
        std::transform( values.begin(), values.end(), values.begin(), [ & ]( float value ) {
            return value + std::abs( min_value );
        } );
    }
}

void GradientDescent::min_max_normalize_target(std::vector<float>& target) {
    float min_value = *std::min_element(target.begin(), target.end());
    float max_value = *std::max_element(target.begin(), target.end());

    for (size_t i = 0; i < target.size(); ++i) {
        if (max_value - min_value != 0) {
            target[i] = (target[i] - min_value) / (max_value - min_value);
        } else {
            target[i] = 0.0f;  // Handle case where all values are the same
        }
    }
}

void GradientDescent::min_max_normalize(std::vector<std::vector<float>>& matrix) {
    for (size_t col = 0; col < matrix[0].size(); ++col) {
        // Find the min and max for the column
        float min_value = std::numeric_limits<float>::max();
        float max_value = std::numeric_limits<float>::lowest();

        for (size_t row = 0; row < matrix.size(); ++row) {
            min_value = std::min(min_value, matrix[row][col]);
            max_value = std::max(max_value, matrix[row][col]);
        }

        // Normalize the column values
        for (size_t row = 0; row < matrix.size(); ++row) {
            if (max_value - min_value != 0) {
                matrix[row][col] = (matrix[row][col] - min_value) / (max_value - min_value);
            } else {
                matrix[row][col] = 0.0f;  // Handle case where all values are the same
            }
        }
    }
}
