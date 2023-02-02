#include <fuzzing/dump.hpp>
#include <utility/assumptions.hpp>
#include <utility/math.hpp>
#include <utility/log.hpp>
#include <set>
#include <map>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  fuzzer_name,
        std::string const&  benchmark_name,
        termination_info const&  info,
        std::size_t const  max_trace_size,
        std::size_t const  max_stdin_bits
        )
{
    ostr << "Accepted the following configuration:\n"
         << "   Fuzzer: " << fuzzer_name << "\n"
         << "   Benchmark: " << benchmark_name << "\n"
         << "   Max executions: " << info.max_driver_executions << "\n"
         << "   Max seconds: " << info.max_fuzzing_seconds << "\n"
         << "   Max trace size: " << max_trace_size << "\n"
         << "   Max stdin bits: " << max_stdin_bits << "\n"
         << "   Allow blind fuzzing: " << std::boolalpha << info.allow_blind_fuzzing << "\n";
    ostr.flush();

    LOG(LSL_INFO,
        "Fuzzing '" << benchmark_name << "' by '" << fuzzer_name << ". "
            << "[Max executions: " << info.max_driver_executions
            << ", Max seconds: " << info.max_fuzzing_seconds
            << ", Allow blind fuzzing: " << std::boolalpha << info.allow_blind_fuzzing
            << ']');
}


void  print_analysis_outcomes(std::ostream&  ostr, analysis_outcomes const&  results, bool const  dump_traces)
{
    switch (results.termination_type)
    {
    case analysis_outcomes::TERMINATION_TYPE::NORMAL:
        ostr << "Fuzzing terminated normally.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::INVARIANT_FAILURE:
        ostr << "Fuzzing early-terminated due to invariant failure.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::ASSUMPTION_FAILURE:
        ostr << "Fuzzing early-terminated due to assumption failure.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::CODE_UNDER_CONSTRUCTION_REACHED:
        ostr << "Fuzzing early-terminated due to reaching code under construction.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::UNEXPECTED_CLIENT_CRASH:
        ostr << "Fuzzing early-terminated due to an unexpected client crash.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_EXCEPTION:
        ostr << "Fuzzing early-terminated due to an unclassified exception.";
        break;
    }
    ostr << " Details:\n   Termination reason: " << results.termination_message << std::endl;

    ostr << "   Executions performed: " << results.num_executions << '\n';
    
    if (results.num_max_trace_size_reached > 0) {
        ostr << "   Times maximum trace size was reached: " << results.num_max_trace_size_reached << '\n';
    }

    ostr << "   Seconds spent: " << results.num_elapsed_seconds << '\n';

    std::set<natural_32_bit>  covered_ids;
    for (instrumentation::location_id const  loc_id : results.covered_branchings)
        covered_ids.insert(loc_id.id);

    std::map<std::pair<natural_32_bit, bool>, std::unordered_set<natural_32_bit> >  uncovered_ids;
    for (auto const&  id_and_branching : results.uncovered_branchings)
        if (covered_ids.count(id_and_branching.first.id) == 0)
            uncovered_ids[{ id_and_branching.first.id, id_and_branching.second }].insert(id_and_branching.first.context_hash);
        else
        {
            uncovered_ids.erase({ id_and_branching.first.id, !id_and_branching.second });
            covered_ids.insert(id_and_branching.first.id);
        }

    ostr << "   Covered branchings [basic block]: " << covered_ids.size() << std::endl;
    for (natural_32_bit const  id : covered_ids)
        ostr << "      " << id << "\n";

    ostr << "   Uncovered branchings [basic block:uncovered branch#num_contexts]: " << uncovered_ids.size() << std::endl;
    for (auto const&  id_and_branching : uncovered_ids)
        ostr << "      " << id_and_branching.first.first << ":"
                         << (id_and_branching.first.second ? "true" : "false") << '#'
                         << id_and_branching.second.size() << "\n";

    ostr << "   Traces forming the coverage: " << results.traces_forming_coverage.size() << std::endl;
    if (dump_traces)
        for (trace_with_coverage_info const&  trace : results.traces_forming_coverage)
        {
            ostr << "   ******************************************\n";
            print_trace_with_coverage_info(ostr, trace, true, true, "   ");
        }

    ostr.flush();

    if (results.termination_type != analysis_outcomes::TERMINATION_TYPE::NORMAL)
        LOG(LSL_ERROR, "Fuzzing did not terminate normally. Reason: " << results.termination_message);
    else
        LOG(LSL_INFO, "Fuzzing terminated normally. Reason: " << results.termination_message);
    if (!results.uncovered_branchings.empty())
    {
        std::stringstream  sstr;
        for (auto const&  id_and_branching : results.uncovered_branchings)
            sstr << id_and_branching.first << ":" << (id_and_branching.second ? "true" : "false") << ", ";
        LOG(LSL_INFO, "Fuzzing did not cover these branchings: " << sstr.str());
    }
}


void  print_trace_with_coverage_info(
        std::ostream&  ostr,
        trace_with_coverage_info const&  trace,
        bool  dump_coverage_info,
        bool  dump_chunks,
        std::string const&  shift
        )
{
    vecu8  byte_values;
    bits_to_bytes(trace.input_stdin, byte_values);

    ostr << shift << "bytes [stdin]{hex}: " << byte_values.size();
    for (natural_32_bit  i = 0U, n = (natural_32_bit)byte_values.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << std::setfill('0') << std::setw(2) << std::hex << (natural_32_bit)byte_values.at(i) << ' ';
    }

    if (dump_chunks)
    {
        veci32  chunk_values;
        for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)trace.input_stdin_counts.size(); i < n; ++i)
        {
            ASSUMPTION(trace.input_stdin_counts.at(i) <= 8U * sizeof(chunk_values.back()));
            chunk_values.push_back(0U);
            for (natural_8_bit  j = 0U, m = trace.input_stdin_counts.at(i) / 8U; j < m; ++j)
                *(((natural_8_bit*)&chunk_values.back()) + j) = byte_values.at(k + j);
            k += trace.input_stdin_counts.at(i) / 8U;
        }

        ostr << '\n' << shift << "chunks [num_bytes:int_value]{dec}: " << chunk_values.size();
        for (natural_32_bit  i = 0U, n = (natural_32_bit)chunk_values.size(); i < n; ++i)
        {
            if (i != 0U) ostr << ',';
            if (i % 8U == 0U) ostr << '\n' << shift << shift;
            ostr << std::dec << (natural_32_bit)trace.input_stdin_counts.at(i) / 8U << ':'
                 << std::dec << chunk_values.at(i);
        }
    }

    if (dump_coverage_info)
    {
        if (!trace.discovered_locations.empty())
        {
            std::set<natural_32_bit>  locations;
            for (auto const&  loc : trace.discovered_locations)
                locations.insert(loc.id);

            ostr << '\n' << shift << "discovered: " << locations.size();
            natural_32_bit  i = 0U;
            for (auto it = locations.begin(); it != locations.end(); ++it, ++i)
            {
                if (i != 0U) ostr << ',';
                if (i % 16U == 0U) ostr << '\n' << shift << shift;
                ostr << std::dec << *it;
            }
        }

        if (!trace.covered_locations.empty())
        {
            std::set<natural_32_bit>  locations;
            for (auto const&  loc : trace.covered_locations)
                locations.insert(loc.id);

            ostr << '\n' << shift << "covered: " << locations.size();
            natural_32_bit  i = 0U;
            for (auto it = locations.begin(); it != locations.end(); ++it, ++i)
            {
                if (i != 0U) ostr << ',';
                if (i % 16U == 0U) ostr << '\n' << shift << shift;
                ostr << std::dec << *it;
            }
        }
    }

    ostr << '\n' << shift << "branchings: " << trace.trace.size();
    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.trace.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << trace.trace.at(i).first.id << (trace.trace.at(i).second ? '+' : '-');
    }

    ostr << std::endl;
}

void  save_traces_with_coverage_infos_to_directory(
        std::filesystem::path const&  output_dir,
        std::vector<trace_with_coverage_info> const&  traces_forming_coverage,
        bool  dump_coverage_info,
        bool  dump_chunks,
        std::string const&  test_name_prefix
        )
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)traces_forming_coverage.size(); i < n; ++i)
    {
        std::filesystem::path const  test_file_path = output_dir / (test_name_prefix + "_" + std::to_string(i + 1U) + ".et");
        std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
        print_trace_with_coverage_info(ostr, traces_forming_coverage.at(i), dump_coverage_info, dump_chunks, "   ");
    }
}


}
