#ifndef FUZZHAMM_IID_FUZZER_IMPROVE_BRANCHING_DIRECTIONS_HPP_INCLUDED
#   define FUZZHAMM_IID_FUZZER_IMPROVE_BRANCHING_DIRECTIONS_HPP_INCLUDED

#   include <fuzzhamm/iid_fuzzer_base.hpp>
#   include <fuzzhamm/execution_trace_utils.hpp>
#   include <utility/std_pair_hash.hpp>
#   include <map>
#   include <unordered_set>
#   include <unordered_map>
#   include <map>

namespace  fuzzhamm {


using namespace instrumentation;


struct  iid_fuzzer_improve_branching_directions : public iid_fuzzer_base
{
    using  tasks_map_key_type = std::pair<coverage_distance_type, std::size_t>;

    struct  tasks_map_value_type
    {
        execution_trace_ptr  trace;
        std::unordered_set<natural_32_bit>  fuzzed_indices;
    };

    using  tasks_map = std::map<tasks_map_key_type, tasks_map_value_type>;

    struct  current_task_info
    {
        tasks_map::iterator  task_iter;
        natural_32_bit  swapped_branch_index;
        sensitivity_fuzzer_base_ptr  sensitivity_fuzzer;
        branching_fuzzer_sequence_ptr  branching_fuzzer;
    };

    struct  pending_new_trace
    {
        execution_trace_ptr  trace;
        natural_32_bit  best_target_record_index;
    };

    explicit  iid_fuzzer_improve_branching_directions(location_id  id);

    bool  done() const override;
    float_64_bit  processing_penalty() const override;

protected:

    void  new_trace(execution_trace_ptr const  trace, std::unordered_set<natural_32_bit> const&  target_branching_indices) override;
    void  update(execution_trace_ptr  sample_trace) override;
    void  generate(vecb&  input_stdin) override;

private:
    void  process_pending_traces();
    bool  select_current_task();
    bool  try_select_current_task_from_value(tasks_map_value_type&  task_value);

    tasks_map  tasks;
    std::unordered_map<std::size_t, coverage_distance_type>  trace_sizes_to_coverages;
    std::vector<pending_new_trace>  pending_new_traces;
    branching_classification  classification;
    iid_branching_direction_switching_stats_map  switching_stats;
    current_task_info  current_task;
};


}

#endif
