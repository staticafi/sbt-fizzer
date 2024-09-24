#pragma once

#include <vector>
#include <functional>

class GradientDescent {
public:
    GradientDescent(float learning_rate = 0.001f, int max_iterations = 10000, float convergence_threshold = 1e-6);

    std::vector<float> optimize(const std::vector<std::vector<float>>& coefficient_matrix, const std::vector<float>& target_vector);

    // Setters for easy modification of parameters
    void setLearningRate(float learning_rate) { _learning_rate = learning_rate; }
    void setMaxIterations(int max_iterations) { _max_iterations = max_iterations; };
    void setConvergenceThreshold(float convergence_threshold) { _convergence_threshold = convergence_threshold; };


private:
    float _learning_rate;
    int _max_iterations;
    float _convergence_threshold;

    std::vector<float> computeGradient(const std::vector<float>& current_solution, const std::vector<std::vector<float>>& coefficient_matrix, const std::vector<float>& target_vector);
    float computeMeanSquaredError(const std::vector<float>& current_solution, const std::vector<std::vector<float>>& coefficient_matrix, const std::vector<float>& target_vector);
    std::vector<float> generateRandomWeights(size_t n);
    float dotProduct(const std::vector<float>& a, const std::vector<float>& b);

};
