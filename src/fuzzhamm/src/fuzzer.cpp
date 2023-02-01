#include <fuzzhamm/fuzzer.hpp>
#include <fuzzhamm/execution_trace.hpp>
#include <fuzzhamm/execution_trace_utils.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


static vecb&  stdin_bits_ref()
{
    std::shared_ptr<iomodels::stdin_replay_bits_then_repeat_85> const stdin_ptr =
                std::dynamic_pointer_cast<iomodels::stdin_replay_bits_then_repeat_85>(iomodels::iomanager::instance().get_stdin());
    ASSUMPTION(stdin_ptr != nullptr);
    return stdin_ptr->bits_ref();
}


fuzzer::fuzzer(termination_info const&  info)
    : fuzzer_base(info)
    , traces()
    , did_branchings()
    , iid_branchings()
    , processed_iid_branching(invalid_location_id())
    , processed_trace(nullptr)
    , constructed_trace(nullptr)
    , seen_trace_hash_codes()
{}


void  fuzzer::on_execution_begin()
{
    if (!traces.empty())
        prepare_did_trace();
    else if (!iid_branchings.empty())
        prepare_iid_trace();
    else { /* Nothing to do. */ }
}


void  fuzzer::on_execution_end()
{
    collect_execution_results();

    if (!traces.empty())
        process_did_trace();
    else if (!iid_branchings.empty())
        process_iid_trace();
    else { /* Nothing to do. */ }

    update_state_by_constructed_trace();

    if (!traces.empty())
        select_did_trace_to_process();
    else if (!iid_branchings.empty())
        select_iid_branching_to_process();
    else
        notify_that_fuzzing_strategy_is_finished();
}


void  fuzzer::collect_execution_results()
{
    constructed_trace = std::make_shared<execution_trace>();
    for (branching_coverage_info const&  info : iomodels::iomanager::instance().get_trace())
    {
        constructed_trace->branching_records.push_back({ info, {}, {}, {}, nullptr });
        hash_combine(
                constructed_trace->hash_code,
                (info.branching_id.uid + (natural_32_bit)info.covered_branch * 123U) * constructed_trace->branching_records.size()
                );
    }

    constructed_trace->input_stdin = iomodels::iomanager::instance().get_stdin()->get_bits();
    constructed_trace->input_stdin_counts = iomodels::iomanager::instance().get_stdin()->get_counts();
}


void  fuzzer::update_state_by_constructed_trace()
{
    if (seen_trace_hash_codes.count(constructed_trace->hash_code) == 0UL)
    {
        seen_trace_hash_codes.insert(constructed_trace->hash_code);

        if (!get_last_trace_discovered_branchings().empty())
        {
            constructed_trace->state = EXECUTION_TRACE_STATE::DISCOVERING_BITS;
            constructed_trace->uncovered_branchings = get_last_trace_discovered_branchings();
            constructed_trace->uncovered_branchings.insert(get_last_trace_uncovered_branchings().begin(), get_last_trace_uncovered_branchings().end());

            traces.insert({ constructed_trace->hash_code, constructed_trace });
        }

        for (auto const&  loc_and_indices : get_last_trace_uncovered_branchings())
            if (did_branchings.count(loc_and_indices.first) == 0ULL)
            {
                auto const  it = iid_branchings.insert({ loc_and_indices.first, nullptr }).first;
                if (it->second == nullptr)
                    it->second = create_iid_fuzzer(loc_and_indices.first);
                it->second->on_new_trace(constructed_trace, loc_and_indices.second);
            }
    }

    constructed_trace = nullptr;

    if (!get_last_trace_covered_branchings().empty())
    {
        if (processed_trace != nullptr && processed_trace->fuzzed_record_idx != -1
                && get_last_trace_covered_branchings().count(
                        processed_trace->branching_records.at(processed_trace->fuzzed_record_idx).coverage_info.branching_id
                        ) != 0ULL)
        {
            processed_trace->fuzzed_record_idx = -1;
            processed_trace = nullptr;
        }
        for (location_id const  id : get_last_trace_covered_branchings())
            iid_branchings.erase(id);
        if (get_last_trace_covered_branchings().count(processed_iid_branching) != 0ULL)
            processed_iid_branching = invalid_location_id();

        std::vector<traces_map::iterator> to_remove;
        for (auto it = traces.begin(); it != traces.end(); ++it)
        {
            for (location_id const  id : get_last_trace_covered_branchings())
            {
                auto loc_it = it->second->uncovered_branchings.find(id);
                if (loc_it != it->second->uncovered_branchings.end())
                {
                    for (auto  idx : loc_it->second)
                        it->second->branching_records.at(idx).fuzzer = nullptr;
                    it->second->uncovered_branchings.erase(loc_it);
                }
            }
            if (it->second->uncovered_branchings.empty())
                to_remove.push_back(it);
        }
        for (auto  it : to_remove)
        {
            if (it->second == processed_trace)
            {
                processed_trace->fuzzed_record_idx = -1;
                processed_trace = nullptr;
            }
            traces.erase(it);
        }
    }
}


void  fuzzer::prepare_did_trace()
{
    ASSUMPTION(!traces.empty());

    if (processed_trace != nullptr)
        switch (processed_trace->state)
        {
        case EXECUTION_TRACE_STATE::DISCOVERING_BITS:
            processed_trace->fuzzer->compute_input(stdin_bits_ref());
            break;
        case EXECUTION_TRACE_STATE::FUZZING_BITS:
            processed_trace->branching_records.at(processed_trace->fuzzed_record_idx).fuzzer->compute_input(stdin_bits_ref());
            break;
        default:
            UNREACHABLE();
        }
}


void  fuzzer::process_did_trace()
{
    ASSUMPTION(!traces.empty());

    if (processed_trace == nullptr)
        return;

    std::size_t const  diverging_branch_index = compute_diverging_branch_index(processed_trace->branching_records, constructed_trace->branching_records);

    switch (processed_trace->state)
    {
    case EXECUTION_TRACE_STATE::DISCOVERING_BITS:
        {
            processed_trace->fuzzer->on_sample(constructed_trace, diverging_branch_index);
            if (processed_trace->fuzzer->done())
            {
                processed_trace->state = EXECUTION_TRACE_STATE::FUZZING_BITS;

                compute_diverged_and_colliding_stdin_bits(processed_trace->branching_records);

                std::vector<std::pair<location_id, natural_32_bit> >  to_remove_uncovered_branchings;
                for (auto const&  loc_and_indices : processed_trace->uncovered_branchings)
                    for (auto  idx : loc_and_indices.second)
                    {
                        execution_trace_record&  rec = processed_trace->branching_records.at(idx);

                        if (rec.sensitive_stdin_bits.empty())
                        {
                            // The branching is most likely 'iid' => we can hardly cover this branching using this trace alone.
                            to_remove_uncovered_branchings.push_back({ loc_and_indices.first, idx });
                            continue;
                        }

                        did_branchings.insert(loc_and_indices.first);
                        iid_branchings.erase(loc_and_indices.first);
                    }
                for (auto const&  loc_and_idx : to_remove_uncovered_branchings)
                {
                    auto const  it = processed_trace->uncovered_branchings.find(loc_and_idx.first);
                    it->second.erase(loc_and_idx.second);
                    if (it->second.empty())
                    {
                        processed_trace->uncovered_branchings.erase(it);
                        if (processed_trace->uncovered_branchings.empty())
                        {
                            traces.erase(processed_trace->hash_code);
                            break;
                        }
                    }
                }

                processed_trace->fuzzer = nullptr;

                processed_trace = nullptr;
            }
        }
        break;
    case EXECUTION_TRACE_STATE::FUZZING_BITS:
        {
            auto&  fuzzed_branch = processed_trace->branching_records.at(processed_trace->fuzzed_record_idx);
            bool const  diverged = processed_trace->fuzzed_record_idx > (integer_32_bit)diverging_branch_index;
            fuzzed_branch.fuzzer->on_sample(
                    constructed_trace->input_stdin,
                    diverged ? std::numeric_limits<coverage_distance_type>::max() :
                                constructed_trace->branching_records.at(processed_trace->fuzzed_record_idx).coverage_info
                                        .distance_to_uncovered_branch,
                    diverged
                    );
            if (fuzzed_branch.fuzzer->done())
            {
                auto it = processed_trace->uncovered_branchings.find(fuzzed_branch.coverage_info.branching_id);
                it->second.erase(processed_trace->fuzzed_record_idx);
                if (it->second.empty())
                {
                    processed_trace->uncovered_branchings.erase(it);
                    if (processed_trace->uncovered_branchings.empty())
                        traces.erase(processed_trace->hash_code);
                }

                fuzzed_branch.fuzzer = nullptr;

                processed_trace->fuzzed_record_idx = -1;
                processed_trace = nullptr;
            }
        }
        break;
    default:
        UNREACHABLE();
    }
}


void  fuzzer::select_did_trace_to_process()
{
    ASSUMPTION(!traces.empty());

    if (processed_trace == nullptr)
    {
        for (auto it = traces.begin(); it != traces.end(); ++it)
            if (it->second->state == EXECUTION_TRACE_STATE::DISCOVERING_BITS)
            {
                processed_trace = it->second;

                if (processed_trace->fuzzer == nullptr)
                    processed_trace->fuzzer = create_sensitivity_fuzzer(processed_trace, true);

                return;
            }

        INVARIANT(processed_trace == nullptr);

        did_branching_selection_penalty  min_penalty;
        for (auto const&  hash_and_trace : traces)
            for (auto const&  loc_and_indices : hash_and_trace.second->uncovered_branchings)
                for (auto  idx : loc_and_indices.second)
                {
                    did_branching_selection_penalty const  penalty(hash_and_trace.second->branching_records.at(idx));
                    if (processed_trace == nullptr || penalty < min_penalty)
                    {
                        min_penalty = penalty;
                        processed_trace = hash_and_trace.second;
                        processed_trace->fuzzed_record_idx = idx;
                    }
                }

        INVARIANT(processed_trace != nullptr && processed_trace->state == EXECUTION_TRACE_STATE::FUZZING_BITS && processed_trace->fuzzed_record_idx != -1);

        execution_trace_record&  rec = processed_trace->branching_records.at(processed_trace->fuzzed_record_idx);
        if (rec.fuzzer == nullptr)
            rec.fuzzer = create_branching_fuzzer_sequence(rec, processed_trace->input_stdin, get_random_generator());
    }
}


void  fuzzer::prepare_iid_trace()
{
    ASSUMPTION(traces.empty() && !iid_branchings.empty() && processed_iid_branching != invalid_location_id());

    auto  fuzzer = iid_branchings.at(processed_iid_branching);
    fuzzer->compute_input(stdin_bits_ref());
}


void  fuzzer::process_iid_trace()
{
    ASSUMPTION(traces.empty() && !iid_branchings.empty() && processed_iid_branching != invalid_location_id());

    auto  fuzzer = iid_branchings.at(processed_iid_branching);
    fuzzer->on_sample(constructed_trace);
    if (fuzzer->done())
    {
        iid_branchings.erase(processed_iid_branching);
        processed_iid_branching = invalid_location_id();
    }
}


void  fuzzer::select_iid_branching_to_process()
{
    ASSUMPTION(traces.empty() && !iid_branchings.empty());

    processed_iid_branching = invalid_location_id();
    float_64_bit  min_processing_penalty = std::numeric_limits<float_64_bit>::max();
    for (auto&  loc_and_fuzzer : iid_branchings)
    {
        INVARIANT(loc_and_fuzzer.second != nullptr);
        float_64_bit const  processing_penalty = loc_and_fuzzer.second->processing_penalty();
        if (processed_iid_branching == invalid_location_id() || processing_penalty < min_processing_penalty)
        {
            processed_iid_branching = loc_and_fuzzer.first;
            min_processing_penalty = processing_penalty;
        }
    }
    INVARIANT(processed_iid_branching != invalid_location_id());
}


}
