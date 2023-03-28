#include <fuzzing/jetklee_analysis.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <connection/kleeient_connector.hpp>

namespace  fuzzing {


jetklee_analysis::jetklee_analysis()
    : state{ READY }
    , node_ptr{ nullptr }
    , statistics{}
{}


bool  jetklee_analysis::is_worth_processing(branching_node* const  tested_node_ptr) const
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready());

    if (tested_node_ptr->jetklee_queued)
        return false;

    if (tested_node_ptr->is_direction_explored(false) && tested_node_ptr->is_direction_explored(true))
        return false;

    // Here should be more advanced heuristic detecting whether JetKlee
    // should be called for this branching or not. 

    if (tested_node_ptr->sensitive_stdin_bits.size() < 8)
        return false;

    return true;
}


void  jetklee_analysis::start(branching_node* const  node_ptr_)
{
    ASSUMPTION(is_ready());
    ASSUMPTION(!node_ptr_->is_direction_explored(false) || !node_ptr_->is_direction_explored(true));

    state = BUSY;
    node_ptr = node_ptr_;

    ++statistics.start_calls;
}


void  jetklee_analysis::stop()
{
    if (!is_busy())
        return;

    node_ptr->jetklee_queued = true;

    state = READY;
    node_ptr = nullptr;
}


bool  jetklee_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (node_ptr->jetklee_queued)
    {
        stop();
        return false;
    }

    connection::kleeient_connector connector(45655);
    connector.wait_for_connection();


    fuzzing::branching_node *node = node_ptr;
    std::vector<bool> trace;
    while (node->predecessor != nullptr)
    {
        trace.push_back(node->predecessor->successor_direction(node));
        node = node->predecessor;
    }
    std::reverse(trace.begin(), trace.end());

    std::vector<uint8_t> bytes;
    connector.get_model(trace, bytes);

    for (natural_8_bit const  byte : bytes)
        for (natural_8_bit  i = 0U; i != 8U; ++i)
            bits_ref.push_back(byte & (1 << (7U - i)));    

    ++statistics.generated_inputs;

    return true;
}


void  jetklee_analysis::process_execution_results(execution_trace_pointer const  trace_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());

    node_ptr->jetklee_queued = true;

    if (node_ptr->is_direction_explored(false) && node_ptr->is_direction_explored(true))
        ++statistics.covered_branchings;
}


}
