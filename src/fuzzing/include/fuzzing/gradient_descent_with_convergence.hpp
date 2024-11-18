#pragma once

#include <map>
#include <optional>
#include <vector>

struct GradientDescentResult {
    std::vector< float > weights;
    std::vector< float > errors;
    std::vector< float > column_count_weighted;
    int iterations;
    float error_mean;
    float error_square_of_mean;
    float error_mean_of_squares;
    float error_variance;
    float variance_threshold;
    float count_threshold;
    bool converged;
};


class GradientDescentNew {
public:
    GradientDescentNew( const std::vector< std::vector< float > >& coefficient_matrix,
                        const std::vector< float >& target_vector,
                        std::map< size_t, float > locked_columns = {},
                        float learning_rate = 0.01f,
                        int max_iterations = 1000,
                        float convergence_threshold = 1e-4,
                        float momentum = 0.9f );

    GradientDescentResult optimize();
    void print_input_matrix();

private:
    std::vector< std::vector< float > > _coefficient_matrix;
    std::vector< float > _target_vector;
    std::vector< std::optional< float > > _locked_columns;
    float _learning_rate;
    int _max_iterations;
    float _convergence_threshold;
    float _momentum;
    bool _debug = false;

    std::vector< float > compute_gradient( const std::vector< float >& current_solution );
    std::vector< float > compute_errors( const std::vector< float >& current_solution );
    float compute_mean_squared_error( const std::vector< float >& errors );
    static std::vector< float > generate_random_weights( size_t n );
    static float dot_product( const std::vector< float >& a, const std::vector< float >& b );
    static float compute_variance( const std::vector< float >& errors );
    static bool compute_convergence( const std::vector< float >& counts_per_column_weighted,
                                     float error_variance,
                                     float error_mean,
                                     float& variance_threshold,
                                     float& count_threshold );
    static float compute_mean( const std::vector< float >& errors );
    std::vector< float > compute_column_count( const std::vector< float >& current_solution );
};