#include <fuzzing/analysis_statistics.hpp>
#include <fuzzing/branching_node.hpp>
#include <chrono>
#include <set>
#include <iterator>

namespace fuzzing {

void analysis_statistics::start_minimization(branching_node* node) {
    initialize_measurement(node);
    populate_outcome_start(measurements[node].minimization_outcome);
    last_measurement = &measurements[node].minimization_outcome;
    last_node = node;
}

void analysis_statistics::stop_minimization()
{
    populate_outcome_stop(measurements[last_node].minimization_outcome);
}

void analysis_statistics::start_jetklee(branching_node* node)
{
    initialize_measurement(node);
    populate_outcome_start(measurements[node].jetklee_outcome);
    last_measurement = &measurements[node].jetklee_outcome;
    last_node = node;
}

void analysis_statistics::stop_jetklee()
{
    populate_outcome_stop(measurements[last_node].jetklee_outcome);
}

void analysis_statistics::stop_last_analysis()
{
    if (last_measurement == nullptr)
        return;
    populate_outcome_stop(*last_measurement);
    last_measurement = nullptr;
}



void analysis_statistics::initialize_measurement(branching_node *node)
{
    if (measurements.contains(node))
        return;

    std::set<natural_32_bit> locations;
    size_t length = 0;
    for (branching_node *it = node; it != nullptr; it = it->predecessor)
    {
        length++;
        locations.emplace(it->id.id);
    }
    std::set<stdin_bit_index> predecessors_sensitive_bits;
    for (branching_node *it = node == nullptr ? node : node->predecessor; it != nullptr; it = it->predecessor)
    {
        predecessors_sensitive_bits.insert(it->sensitive_stdin_bits.begin(), it->sensitive_stdin_bits.end());
    }

    // node->sensitive_stdin_bits is unordered_set so we have to use this
    std::set<stdin_bit_index> all_sensitive_bits;
    std::set<stdin_bit_index> overlapping_sensitive_bits;
    all_sensitive_bits.insert(predecessors_sensitive_bits.begin(), predecessors_sensitive_bits.end());
    all_sensitive_bits.insert(node->sensitive_stdin_bits.begin(), node->sensitive_stdin_bits.end());
    std::copy_if(predecessors_sensitive_bits.begin(), predecessors_sensitive_bits.end(),
        std::inserter(overlapping_sensitive_bits, overlapping_sensitive_bits.begin()),
        [node](stdin_bit_index idx){return node->sensitive_stdin_bits.contains(idx);} );;

    measurement m;
    m.total_sensitive_bits = all_sensitive_bits.size();
    m.branching_sensitive_bits = node->sensitive_stdin_bits.size();
    m.overlapping_sensitive_bits = overlapping_sensitive_bits.size();
    m.total_read_bits = node->best_stdin->size();
    m.trace_length = length;
    m.unique_locations = locations.size();
    m.node_id = node->id.id;
    m.node_hash = node->id.context_hash;
    measurements[node] = m;
}

void analysis_statistics::populate_outcome_start(outcome &o)
{
    o.started = true;
    o.cpu_start = std::clock();
    o.wall_start = std::chrono::system_clock::now();

}

void analysis_statistics::populate_outcome_stop(outcome &o)
{
    o.stopped = true;
    o.cpu_stop = std::clock();
    o.wall_stop = std::chrono::system_clock::now();
    o.generated_inputs = 1; // TODO
}

bool analysis_statistics::performed_minimization(branching_node *node) 
{
    return measurements.contains(node) && measurements[node].minimization_outcome.stopped;
}

bool analysis_statistics::performed_jetklee(branching_node *node)
{
    return measurements.contains(node) && measurements[node].jetklee_outcome.stopped;
}

branching_node* analysis_statistics::get_last_node()
{
    return last_node;
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
    ostr << "branching\t"
         << "trace_length\t"
         << "unique_locations\t"
         << "total_sensitive_bits\t"
         << "branching_sensitive_bits\t"
         << "overlapping_sensitive_bits\t"
         << "total_read_bits\t"
         << "minimization_wall_time\t"
         << "minimization_cpu_time\t"
         << "jetklee_wall_time\t"
         << "jetklee_cpu_time" << std::endl;
    for (auto const& it : measurements) {
        auto m = it.second;
        
        ostr << m.node_id << "!" << m.node_hash << "\t"
             << m.trace_length << "\t"
             << m.unique_locations << "\t"
             << m.total_sensitive_bits << "\t"
             << m.branching_sensitive_bits << "\t"
             << m.overlapping_sensitive_bits << "\t"
             << m.total_read_bits << "\t";
        if (m.minimization_outcome.stopped) {
            double minimization_wall_time = wall_duration(m.minimization_outcome.wall_start, m.minimization_outcome.wall_stop);
            double minimization_cpu_time = cpu_duration(m.minimization_outcome.cpu_start, m.minimization_outcome.cpu_stop);
            ostr << minimization_wall_time << "\t"
                 << minimization_cpu_time << "\t";
        } else {
            ostr << "N/A\tN/A\t";
        }
        if (m.jetklee_outcome.stopped) {
            double jetklee_wall_time = wall_duration(m.jetklee_outcome.wall_start, m.jetklee_outcome.wall_stop);
            double jetklee_cpu_time = cpu_duration(m.jetklee_outcome.cpu_start, m.jetklee_outcome.cpu_stop);
            ostr << jetklee_wall_time << "\t"
                 << jetklee_cpu_time << "\t";
        } else {
            ostr << "N/A\tN/A\t";
        }
        ostr << std::endl;
    }

    ostr << "=== analysis statistics end ===" << std::endl;
}

}
