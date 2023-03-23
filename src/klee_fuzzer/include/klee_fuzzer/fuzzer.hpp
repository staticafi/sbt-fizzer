#ifndef KLEE_FUZZER_FUZZER_HPP_INCLUDED
#define KLEE_FUZZER_FUZZER_HPP_INCLUDED

#include <fuzzhamm/execution_trace.hpp>
#include <fuzzhamm/iid_fuzzer_base.hpp>
#include <fuzzing/fuzzer_base.hpp>
#include <unordered_map>
#include <unordered_set>
#include <memory>


namespace klee_fuzzer {


using namespace fuzzing;


using  traces_map = std::unordered_map<fuzzhamm::execution_trace_hash_code, fuzzhamm::execution_trace_ptr>;
using  directly_input_dependent_branchings_set = std::unordered_set<location_id>;

using  indirectly_input_dependent_branchings_map = std::unordered_map<location_id, fuzzhamm::iid_fuzzer_base_ptr>;


struct  fuzzer : public fuzzer_base
{
    explicit fuzzer(termination_info const&  info);

protected:

    void  on_execution_begin() override;
    void  on_execution_end() override;

private:
    void  collect_execution_results();
    void  update_state_by_constructed_trace();

    void  prepare_did_trace();
    void  process_did_trace();
    void  select_did_trace_to_process();

    void  prepare_iid_trace();
    void  process_iid_trace();
    void  select_iid_branching_to_process();

    traces_map  traces;
    directly_input_dependent_branchings_set  did_branchings;
    indirectly_input_dependent_branchings_map  iid_branchings;
    location_id  processed_iid_branching;
    fuzzhamm::execution_trace_ptr  processed_trace;
    fuzzhamm::execution_trace_ptr  constructed_trace;
    std::unordered_set<fuzzhamm::execution_trace_hash_code>  seen_trace_hash_codes;
};


}

#endif
