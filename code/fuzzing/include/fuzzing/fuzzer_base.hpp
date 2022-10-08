#ifndef FUZZING_FUZZER_BASE_HPP_INCLUDED
#   define FUZZING_FUZZER_BASE_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/random.hpp>
#   include <unordered_map>
#   include <unordered_set>
#   include <chrono>
#   include <memory>
#   include <limits>
#   include <type_traits>
#   include <stdexcept>

namespace  fuzzing {


using namespace instrumentation;


struct  fuzzer_interrupt_exception : public std::logic_error
{
    explicit fuzzer_interrupt_exception(char const* const message) : std::logic_error(message) {}
    explicit fuzzer_interrupt_exception(const std::string& message) : std::logic_error(message) {}
};


struct branch_coverage_info
{
    bool true_branch_covered;
    bool false_branch_covered;
};


struct  fuzzer_base
{
    explicit fuzzer_base(termination_info const&  info);
    virtual ~fuzzer_base() = default;

    random_generator_for_natural_32_bit&  get_random_generator() { return generator; }
    natural_8_bit  get_random_byte() { return (natural_8_bit)get_random_natural_32_bit_in_range(0U, 255U, get_random_generator()); }

    std::unordered_map<location_id, branch_coverage_info> const&  get_branch_coverage_info() const { return coverage_info; }

    termination_info const& get_termination_info() const { return termination_props; }
    long  num_remaining_driver_executions() const { return (long)termination_props.max_driver_executions - (long)num_driver_executions; }
    long  num_remaining_seconds() const { return (long)termination_props.max_fuzzing_seconds - get_elapsed_seconds(); }
    natural_32_bit  get_performed_driver_executions() const { return num_driver_executions; }
    natural_32_bit  get_num_max_trace_size_reached() const { return num_max_trace_size_reached; }
    long  get_elapsed_seconds() const { return (long)std::chrono::duration_cast<std::chrono::seconds>(time_point_current - time_point_start).count(); }
    natural_32_bit  get_num_covered_branchings() const { return (natural_32_bit)coverage_info.size() - num_uncovered_branchings; }
    natural_32_bit  get_num_uncovered_branchings() const { return num_uncovered_branchings; }

    std::unordered_set<location_id> const&  get_last_trace_covered_branchings() const { return last_trace_covered_branchings; }
    std::unordered_map<location_id, std::unordered_set<natural_32_bit> > const&  get_last_trace_discovered_branchings() const
    { return last_trace_discovered_branchings; }
    std::unordered_map<location_id, std::unordered_set<natural_32_bit> > const&  get_last_trace_uncovered_branchings() const
    { return last_trace_uncovered_branchings; }

    std::vector<trace_with_coverage_info> const  get_traces_forming_coverage() const { return traces_forming_coverage; }

    void  _on_driver_begin();
    void  _on_driver_end();

protected:

    virtual void  on_execution_begin() = 0;
    virtual void  on_execution_end() = 0;

    void  notify_that_fuzzing_strategy_is_finished() { fuzzing_strategy_finished = true; }

private:
    termination_info termination_props;
    natural_32_bit  num_driver_executions;
    natural_32_bit num_max_trace_size_reached;
    std::chrono::steady_clock::time_point  time_point_start;
    std::chrono::steady_clock::time_point  time_point_current;
    random_generator_for_natural_32_bit   generator;

    std::unordered_map<location_id, branch_coverage_info>  coverage_info;
    natural_32_bit  num_uncovered_branchings;

    std::unordered_set<location_id>  last_trace_covered_branchings;
    std::unordered_map<location_id, std::unordered_set<natural_32_bit> >  last_trace_discovered_branchings;
    std::unordered_map<location_id, std::unordered_set<natural_32_bit> >  last_trace_uncovered_branchings;

    std::vector<trace_with_coverage_info>  traces_forming_coverage;

    bool  fuzzing_strategy_finished;
};


template<typename child_type>
inline std::shared_ptr<fuzzer_base> create_fuzzer(termination_info const&  info)
{
    static_assert(std::is_convertible<child_type*, fuzzer_base*>::value, "The constructed fuzzer must be a child of 'fuzze_base' class.");
    return std::make_shared<child_type>(info);
}


}

#endif
