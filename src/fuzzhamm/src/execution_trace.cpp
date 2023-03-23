#include <fuzzhamm/execution_trace.hpp>

namespace  fuzzhamm {


execution_trace::execution_trace()
    : hash_code(0ULL)
    , state(EXECUTION_TRACE_STATE::CONSTRUCTION)
    , branching_records()
    , uncovered_branchings()
    , input_stdin()
    , input_stdin_counts()
    , fuzzer(nullptr)
    , sensitive_stdin_bits()
    , fuzzed_record_idx(-1)
    , feasible(true)
{}


}
