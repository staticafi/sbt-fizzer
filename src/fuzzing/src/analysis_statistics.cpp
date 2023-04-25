#include <fuzzing/analysis_statistics.hpp>
#include <fuzzing/branching_node.hpp>
#include <chrono>

namespace fuzzing {

void analysis_statistics::start_minimization(branching_node* node, bool direction) {
    initialize_measurement(node);
    populate_outcome_start(measurements[node].minimization_outcome);
    last_direction = direction;
    last_node = node;
}

void analysis_statistics::stop_minimization()
{
    populate_outcome_stop(measurements[last_node].minimization_outcome);
}

void analysis_statistics::start_jetklee(branching_node* node, bool direction)
{
    initialize_measurement(node);
    populate_outcome_start(measurements[node].jetklee_outcome);
    last_direction = direction;
    last_node = node;
}

void analysis_statistics::stop_jetklee()
{
    populate_outcome_stop(measurements[last_node].jetklee_outcome);
}

void analysis_statistics::initialize_measurement(branching_node *node)
{
    if (measurements.contains(node))
        return;

    measurement m;
    m.total_sensitive_bits = node->sensitive_stdin_bits.size();
    m.unique_sensitive_bits = 0; // TODO
    m.total_read_bits = node->best_stdin->size();
    m.trace_length = 0;
    branching_node *it = node;
    while (it != nullptr)
    {
        it = it->predecessor;
        m.trace_length++;
    }

    measurements[node] = m;
}

void analysis_statistics::populate_outcome_start(outcome &o)
{
    o.measured = true;
    o.cpu_start = std::clock();
    o.wall_start = std::chrono::system_clock::now();

}

void analysis_statistics::populate_outcome_stop(outcome &o)
{
    o.cpu_stop = std::clock();
    o.wall_stop = std::chrono::system_clock::now();
    o.generated_inputs = 1; // TODO
}

bool analysis_statistics::performed_minimization(branching_node *node) 
{
    return measurements.contains(node) && measurements[node].minimization_outcome.measured;
}

bool analysis_statistics::performed_jetklee(branching_node *node)
{
    return measurements.contains(node) && measurements[node].jetklee_outcome.measured;
}

branching_node* analysis_statistics::get_last_node()
{
    return last_node;
}

bool analysis_statistics::get_last_direction()
{
    return last_direction;
}

// durations in milliseconds
double cpu_duration(clock_t from, clock_t to)
{
    return (to - from) * 1000.0 / CLOCKS_PER_SEC;
}

double wall_duration(wall_time from, wall_time to)
{
    auto from_microseconds = std::chrono::time_point_cast<std::chrono::microseconds>(from);
    auto to_microseconds = std::chrono::time_point_cast<std::chrono::microseconds>(to);
    return (to_microseconds - from_microseconds).count() / 1000.0;
}

void analysis_statistics::dump(std::ostream& ostr) const
{
    ostr << "=== analysis statistics begin ===" << std::endl;
    ostr << "trace_length\t"
         << "unique_sensitive_bits\t"
         << "total_sensitive_bits\t"
         << "total_read_bits\t"
         << "minimization_wall_time\t"
         << "jetklee_wall_time\t"
         << "minimization_cpu_time\t"
         << "jetklee_cpu_time" << std::endl;
    for (auto const& it : measurements) {
        auto m = it.second;
        if (!m.jetklee_outcome.measured || !m.minimization_outcome.measured)
            continue;
        
        double minimization_cpu_time = cpu_duration(m.minimization_outcome.cpu_start, m.minimization_outcome.cpu_stop);
        double jetklee_cpu_time = cpu_duration(m.jetklee_outcome.cpu_start, m.jetklee_outcome.cpu_stop);
        double minimization_wall_time = wall_duration(m.minimization_outcome.wall_start, m.minimization_outcome.wall_stop);
        double jetklee_wall_time = wall_duration(m.jetklee_outcome.wall_start, m.jetklee_outcome.wall_stop);
        
        ostr << m.trace_length << "\t"
             << m.unique_sensitive_bits << "\t"
             << m.total_sensitive_bits << "\t"
             << m.total_read_bits << "\t"
             << minimization_wall_time << "\t"
             << jetklee_wall_time << "\t"
             << minimization_cpu_time << "\t"
             << jetklee_cpu_time << "\t" << std::endl;
    }
    ostr << "";

    ostr << "=== analysis statistics end ===" << std::endl;
}

}
