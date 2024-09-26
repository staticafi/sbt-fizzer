#pragma once

#include <vector>

class GradientDescent {
    /*
        # Improvements
        - Learning rate optimization(Adaptive learning rate)
        - Feature scaling
        - Momentum
        - Mini-batch gradient descent
    */
public:
    GradientDescent( const std::vector< std::vector< float > >& coefficient_matrix,
                     const std::vector< float >& target_vector,
                     float learning_rate = 0.001f,
                     int max_iterations = 10000,
                     float convergence_threshold = 1e-6 );

    std::vector< float > optimize();

    // Setters for easy modification of parameters
    void setLearningRate( float learning_rate ) { _learning_rate = learning_rate; }
    void setMaxIterations( int max_iterations ) { _max_iterations = max_iterations; }
    void setConvergenceThreshold( float convergence_threshold )
    {
        _convergence_threshold = convergence_threshold;
    }

private:
    const std::vector< std::vector< float > >& _coefficient_matrix;
    const std::vector< float >& _target_vector;
    float _learning_rate;
    int _max_iterations;
    float _convergence_threshold;
    bool _debug = false;

    std::vector< float > computeGradient( const std::vector< float >& current_solution );
    float computeMeanSquaredError( const std::vector< float >& current_solution );
    static std::vector< float > generateRandomWeights( size_t n );
    static float dotProduct( const std::vector< float >& a, const std::vector< float >& b );
    static void rescale( std::vector< float >& values, float min_value, float max_value );
};