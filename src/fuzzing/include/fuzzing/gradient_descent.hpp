#pragma once

#include <vector>

/*
    # Improvements
    - Learning rate optimization(Adaptive learning rate)
    - Feature scaling
    - Momentum
    - Mini-batch gradient descent
*/

class GradientDescent {
public:
    GradientDescent( const std::vector< std::vector< float > >& coefficient_matrix,
                     const std::vector< float >& target_vector,
                     float learning_rate = 0.001f,
                     int max_iterations = 10000,
                     float convergence_threshold = 1e-6,
                     float momentum = 0.9f); 

    std::vector< float > optimize(int batch_size = 32);  // Added batch_size parameter

    // Setters for easy modification of parameters
    void set_learning_rate( float learning_rate ) { _learning_rate = learning_rate; }
    void set_max_iterations( int max_iterations ) { _max_iterations = max_iterations; }
    void set_convergence_threshold( float convergence_threshold )
    {
        _convergence_threshold = convergence_threshold;
    }
    void set_momentum(float momentum) { _momentum = momentum; }

private:
    std::vector< std::vector< float > > _coefficient_matrix;
    std::vector< float > _target_vector;
    float _learning_rate;
    int _max_iterations;
    float _convergence_threshold;
    float _momentum;
    bool _debug = false;

    std::vector< float > compute_gradient( const std::vector< float >& current_solution );
    float compute_mean_squared_error( const std::vector< float >& current_solution );
    static std::vector< float > generate_random_weights( size_t n );
    static float dot_product( const std::vector< float >& a, const std::vector< float >& b );
    static void rescale( std::vector< float >& values, float min_value, float max_value );
    static void add_smallest_value( std::vector< float >& values );
    void min_max_normalize(std::vector<std::vector<float>>& matrix);
    void min_max_normalize_target(std::vector<float>& target);

    // New methods for mini-batch gradient descent
    void shuffle_data();
    template<typename T>
    std::vector<T> get_batch(const std::vector<T>& data, size_t start, size_t end);
    std::vector<float> compute_batch_gradient(const std::vector<float>& current_solution, const std::vector<std::vector<float>>& batch_coefficients, const std::vector<float>& batch_target);
};
