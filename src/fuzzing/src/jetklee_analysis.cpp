#include <fuzzing/jetklee_analysis.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <connection/kleeient_connector.hpp>

namespace  fuzzing {


jetklee_analysis::jetklee_analysis(std::unique_ptr<connection::kleeient_connector> kleeient_connector)
    : state{ READY }
    , node_ptr{ nullptr }
    , statistics{}
    , kleeient_connector{ std::move(kleeient_connector) }
{}


bool  jetklee_analysis::is_worth_processing(branching_node* const  tested_node_ptr) const
{
    TMPROF_BLOCK();

    ASSUMPTION(is_ready());

    if (tested_node_ptr->jetklee_queued)
        return false;

    if (tested_node_ptr->is_direction_explored(false) && tested_node_ptr->is_direction_explored(true))
        return false;

    // Heuristic obtained via logistic regressio
    if (tested_node_ptr->sensitive_stdin_bits.size() <= 18)
        return false;

    return true;
}


void  jetklee_analysis::start(branching_node* const  node_ptr_)
{
    ASSUMPTION(is_ready());

    state = BUSY;
    node_ptr = node_ptr_;
    flipped_last_branching = false;
    kept_last_branching = false;

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

std::vector<bool>  jetklee_analysis::prepare_trace(branching_node *node)
{
    std::vector<br_instr_coverage_info> const  br_info_trace {
        node->best_br_instr_trace->begin(),
        std::next(node->best_br_instr_trace->begin(),
            std::min((size_t) node->best_trace->at(node->trace_index).idx_to_br_instr + 1,
                     node->best_br_instr_trace->size()))
    };

    std::vector<bool> jetklee_trace;
    for (auto &it : br_info_trace)
    {
        jetklee_trace.push_back(it.covered_branch);
    }

    if (!flipped_last_branching)
    {
        jetklee_trace.back() = !jetklee_trace.back();
        flipped_last_branching = true;
    }
    else
    {
        kept_last_branching = true;
    }

    return jetklee_trace;
}

bool  jetklee_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (node_ptr->jetklee_queued && flipped_last_branching && kept_last_branching)
    {
        node_ptr->minimization_performed = true;
        node_ptr->jetklee_performed = true;
        stop();
        return false;
    }

    std::vector<bool> jetklee_trace = prepare_trace(node_ptr);
    std::vector<uint8_t> bytes;
    if (!kleeient_connector->get_model(jetklee_trace, bytes))
        return true;

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
