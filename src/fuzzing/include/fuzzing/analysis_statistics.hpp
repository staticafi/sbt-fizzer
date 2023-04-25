#ifndef FUZZING_ANALYSIS_STATISTICS_HPP_INCLUDED
#define FUZZING_ANALYSIS_STATISTICS_HPP_INCLUDED

#include <map>
#include <fuzzing/branching_node.hpp>
#include <chrono>

namespace  fuzzing {
using wall_time = std::chrono::time_point<std::chrono::system_clock>;

struct outcome
{
    bool measured = false;
    clock_t cpu_start = 0;
    clock_t cpu_stop = 0;
    wall_time wall_start {};
    wall_time wall_stop {};
    size_t generated_inputs = 0;
};

struct measurement
{
    size_t unique_sensitive_bits = 0;
    size_t total_sensitive_bits = 0;
    size_t total_read_bits = 0;
    size_t trace_length = 0;
    branching_node *node = 0;
    outcome minimization_outcome {};
    outcome jetklee_outcome {};
};

struct analysis_statistics
{
public:
    void start_minimization(branching_node *node, bool direction);
    void stop_minimization();
    void start_jetklee(branching_node *node, bool direction);
    void stop_jetklee();
    bool performed_minimization(branching_node *node);
    bool performed_jetklee(branching_node *node);
    branching_node *get_last_node();
    bool get_last_direction();
    void dump(std::ostream &ostr) const;
private:
    void initialize_measurement(branching_node *node);
    void populate_outcome_start(outcome& outcome);
    void populate_outcome_stop(outcome& outcome);
    std::map<branching_node*, measurement> measurements;
    branching_node* last_node;
    bool last_direction = false;
};


}

#endif
