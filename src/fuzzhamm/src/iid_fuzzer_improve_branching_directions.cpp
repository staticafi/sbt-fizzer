#include <fuzzhamm/iid_fuzzer_improve_branching_directions.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


iid_fuzzer_improve_branching_directions::iid_fuzzer_improve_branching_directions(location_id const  id)
    : iid_fuzzer_base(id)
    , tasks()
    , trace_sizes_to_coverages()
    , pending_new_traces()
    , classification()
    , switching_stats()
    , current_task{ tasks.end(), 0U, nullptr } // Initialised to an invalid task id.
{}


bool  iid_fuzzer_improve_branching_directions::done() const
{
    return tasks.empty();
}


float_64_bit  iid_fuzzer_improve_branching_directions::processing_penalty() const
{
    return done() ? std::numeric_limits<float_64_bit>::max() : tasks.begin()->first.first;
}


void  iid_fuzzer_improve_branching_directions::new_trace(
        execution_trace_ptr const  trace,
        std::unordered_set<natural_32_bit> const&  target_branching_indices
        )
{
    ASSUMPTION(trace->branching_records.at(*target_branching_indices.begin()).coverage_info.branching_id == loc_id());

    pending_new_traces.push_back({
            trace,
            index_of_branching_record_with_min_coverage_distance(
                    trace->branching_records, target_branching_indices.begin(), target_branching_indices.end()
                    )
            });
}


void  iid_fuzzer_improve_branching_directions::update(execution_trace_ptr const  sample_trace)
{
    if (current_task.task_iter == tasks.end())
        return;

    std::size_t const  diverging_branch_index = compute_diverging_branch_index(
            current_task.task_iter->second.trace->branching_records,
            sample_trace->branching_records,
            current_task.swapped_branch_index + 1ULL
            );
    switch (current_task.task_iter->second.trace->state)
    {
        case EXECUTION_TRACE_STATE::DISCOVERING_BITS:
            current_task.sensitivity_fuzzer->on_sample(sample_trace, diverging_branch_index);
            if (current_task.sensitivity_fuzzer->done())
            {
                compute_diverged_and_colliding_stdin_bits(current_task.task_iter->second.trace->branching_records);

                current_task.task_iter->second.trace->state = EXECUTION_TRACE_STATE::FUZZING_BITS;
                if (!try_select_current_task_from_value(current_task.task_iter->second))
                    current_task.task_iter = tasks.end();
            }
            return;
        case EXECUTION_TRACE_STATE::FUZZING_BITS:
            {
                bool const  diverged = current_task.swapped_branch_index > (integer_32_bit)diverging_branch_index;
                current_task.branching_fuzzer->on_sample(
                        sample_trace->input_stdin,
                        diverged ? std::numeric_limits<coverage_distance_type>::max() :
                                   sample_trace->branching_records.at(current_task.swapped_branch_index).coverage_info.distance_to_uncovered_branch,
                        diverged
                        );
                if (current_task.swapped_branch_index != (integer_32_bit)diverging_branch_index)
                {
                    // The branching fuzzer have not managed to switch the chosen branching yet.

                    if (current_task.branching_fuzzer->done())
                        current_task.task_iter = tasks.end();

                    return;
                }
            }
            break;
        default: UNREACHABLE(); break;
    }

    // The chosen branching was switched => the current task is done.

    branching_coverage_info const&  coverage_info = current_task.task_iter->second.trace->branching_records.at(current_task.swapped_branch_index).coverage_info;

    iid_branching_direction_switching_stats&  stats = switching_stats.at({ coverage_info.branching_id, coverage_info.covered_branch });

    natural_32_bit const  index = index_of_branching_record_with_min_coverage_distance(sample_trace->branching_records, loc_id());

    if (index < (natural_32_bit)sample_trace->branching_records.size())
    {
        ++stats.num_target_hit_samples;

        coverage_distance_type const  distance = sample_trace->branching_records.at(index).coverage_info.distance_to_uncovered_branch;

        stats.sum_of_produced_coverage_changes += distance - current_task.task_iter->first.first;

        pending_new_traces.push_back({ sample_trace, index });
    }
    else // Missed the target location.
        ++stats.num_target_miss_samples;

    current_task.task_iter = tasks.end();
}


void  iid_fuzzer_improve_branching_directions::generate(vecb&  input_stdin)
{
    bool  has_current_task = current_task.task_iter != tasks.end();
    if (!has_current_task)
    {
        process_pending_traces();
        has_current_task = select_current_task();
    }

    if (has_current_task)
        switch (current_task.task_iter->second.trace->state)
        {
            case EXECUTION_TRACE_STATE::DISCOVERING_BITS:
                current_task.sensitivity_fuzzer->compute_input(input_stdin);
                break;
            case EXECUTION_TRACE_STATE::FUZZING_BITS:
                current_task.branching_fuzzer->compute_input(input_stdin);
                break;
            default: UNREACHABLE(); break;
        }
}


void  iid_fuzzer_improve_branching_directions::process_pending_traces()
{
    while (!pending_new_traces.empty())
    {
        pending_new_trace const&  pending = pending_new_traces.back();

        branching_classification  trace_classification;
        classify_branchings(pending.trace->branching_records, trace_classification);
        classification.merge(trace_classification);

        tasks_map_key_type const  key{
                pending.trace->branching_records.at(pending.best_target_record_index).coverage_info.distance_to_uncovered_branch,
                pending.trace->branching_records.size()
                };

        auto  it = trace_sizes_to_coverages.find(key.second);
        if (it == trace_sizes_to_coverages.end())
        {
            it = trace_sizes_to_coverages.insert({ key.second, key.first }).first;
            tasks.insert({ key, { pending.trace, {} } });
        }
        else if (key.first < it->second)
        {
            tasks.erase({ it->second, it->first });
            it->second = key.first;
            tasks.insert({ key, { pending.trace, {} } });
        }

        pending_new_traces.pop_back();
    }
}


bool  iid_fuzzer_improve_branching_directions::select_current_task()
{
    while (!tasks.empty())
    {
        if (try_select_current_task_from_value(tasks.begin()->second))
            return true;
        tasks.erase(tasks.begin());
    }
    return false;
}


bool  iid_fuzzer_improve_branching_directions::try_select_current_task_from_value(tasks_map_value_type&  task_value)
{
    switch (task_value.trace->state)
    {
        case EXECUTION_TRACE_STATE::CONSTRUCTION:
            task_value.trace->state = EXECUTION_TRACE_STATE::DISCOVERING_BITS;
            [[fallthrough]];
        case EXECUTION_TRACE_STATE::DISCOVERING_BITS:
            current_task.task_iter = tasks.begin();
            current_task.swapped_branch_index = std::numeric_limits<natural_32_bit>::max();
            current_task.sensitivity_fuzzer = create_sensitivity_fuzzer(task_value.trace, false);
            current_task.branching_fuzzer = nullptr;
            return true;
        case EXECUTION_TRACE_STATE::FUZZING_BITS:
            break; // We must choose a branching to be switched.
        default: UNREACHABLE(); break;
    }

    natural_32_bit const  end = (natural_32_bit)task_value.trace->branching_records.size();
    natural_32_bit  best_index = end;
    iid_branching_selection_penalty  best_penalty;
    for (natural_32_bit  i = 0U; i < end; ++i)
    {
        execution_trace_record const&  rec = task_value.trace->branching_records.at(i);
        if (rec.coverage_info.branching_id == loc_id() || rec.sensitive_stdin_bits.empty() || task_value.fuzzed_indices.count(i) != 0ULL)
            continue;

        iid_branching_selection_penalty const  penalty({ rec.coverage_info.branching_id, rec.coverage_info.covered_branch }, classification, switching_stats);
        if (best_index == end || penalty < best_penalty)
        {
            best_index = i;
            best_penalty = penalty;
        }
    }
    if (best_index < end)
    {
        task_value.fuzzed_indices.insert(best_index);

        current_task.task_iter = tasks.begin();
        current_task.swapped_branch_index = best_index;
        current_task.sensitivity_fuzzer = nullptr;
        current_task.branching_fuzzer = create_branching_fuzzer_sequence(
                task_value.trace->branching_records.at(best_index),
                task_value.trace->input_stdin,
                get_generator()
                );

        return true;
    }

    return false;
}


}
