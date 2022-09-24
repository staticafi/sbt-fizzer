#include <fuzzing/dump.hpp>
#include <utility/assumptions.hpp>
#include <utility/math.hpp>
#include <utility/log.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  fuzzer_name,
        std::string const&  benchmark_name,
        termination_info const&  info
        )
{
    ostr << "Accepted the following configuration:\n"
         << "   Fuzzer: " << fuzzer_name << "\n"
         << "   Benchmark: " << benchmark_name << "\n"
         << "   Max executions: " << info.max_driver_executions << "\n"
         << "   Max seconds: " << info.max_fuzzing_seconds << "\n"
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
    case analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_EXCEPTION:
        ostr << "Fuzzing early-terminated due to an unclassified exception.";
        break;
    }
    ostr << " Details:\n   Termination reason: " << results.termination_message << std::endl;

    ostr << "   Executions performed: " << results.num_executions << '\n'
         << "   Seconds spent: " << results.num_elapsed_seconds << '\n'
         ;

    ostr << "   Covered branchings [basic block]: " << results.covered_branchings.size() << std::endl;
    for (instrumentation::location_id const  id : results.covered_branchings)
        ostr << "      " << id << "\n";

    ostr << "   Uncovered branchings [basic block, uncovered branch]: " << results.uncovered_branchings.size() << std::endl;
    for (auto const&  id_and_branching : results.uncovered_branchings)
        ostr << "      " << id_and_branching.first << ":" << (id_and_branching.second ? "true" : "false") << "\n";

    ostr << "   Traces forming the coverage: " << results.traces_forming_coverage.size() << std::endl;
    if (dump_traces)
        for (trace_with_coverage_info const&  trace : results.traces_forming_coverage)
        {
            ostr << "   ******************************************\n";
            print_trace_with_coverage_info(ostr, trace, true, false, "   ");
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

    vecu32  chunk_values;
    for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)trace.input_stdin_counts.size(); i < n; ++i)
    {
        ASSUMPTION(trace.input_stdin_counts.at(i) <= 8U * sizeof(chunk_values.back()));
        chunk_values.push_back(0U);
        for (natural_8_bit  j = 0U, m = trace.input_stdin_counts.at(i) / 8U; j < m; ++j)
            *(((natural_8_bit*)&chunk_values.back()) + j) = byte_values.at(k + j);
        k += trace.input_stdin_counts.at(i) / 8U;
    }

    ostr << shift << "bytes [stdin, hex]: " << byte_values.size();
    for (natural_32_bit  i = 0U, n = (natural_32_bit)byte_values.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << std::setfill('0') << std::setw(2) << std::hex << (natural_32_bit)byte_values.at(i) << ' ';
    }

    if (dump_chunks)
    {
        ostr << '\n' << shift << "chunks [stdin, dec, uint]: " << chunk_values.size();
        for (natural_32_bit  i = 0U, n = (natural_32_bit)chunk_values.size(); i < n; ++i)
        {
            if (i != 0U) ostr << ',';
            if (i % 8U == 0U) ostr << '\n' << shift << shift;
            ostr << std::dec << (natural_32_bit)trace.input_stdin_counts.at(i) / 8U << ':'
                 << std::dec << (natural_32_bit)chunk_values.at(i);
        }
    }

    if (dump_coverage_info)
    {
        if (!trace.discovered_locations.empty())
        {
            ostr << '\n' << shift << "discovered: " << trace.discovered_locations.size();
            std::vector<instrumentation::location_id> const  locations(trace.discovered_locations.begin(), trace.discovered_locations.end());
            for (natural_32_bit  i = 0U, n = (natural_32_bit)locations.size(); i < n; ++i)
            {
                if (i != 0U) ostr << ',';
                if (i % 16U == 0U) ostr << '\n' << shift << shift;
                ostr << std::dec << locations.at(i);
            }
        }

        if (!trace.covered_locations.empty())
        {
            ostr << '\n' << shift << "covered: " << trace.covered_locations.size();
            std::vector<instrumentation::location_id> const  locations(trace.covered_locations.begin(), trace.covered_locations.end());
            for (natural_32_bit  i = 0U, n = (natural_32_bit)locations.size(); i < n; ++i)
            {
                if (i != 0U) ostr << ',';
                if (i % 16U == 0U) ostr << '\n' << shift << shift;
                ostr << std::dec << locations.at(i);
            }
        }
    }

    ostr << '\n' << shift << "branchings: " << trace.trace.size();
    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.trace.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << trace.trace.at(i).first << (trace.trace.at(i).second ? '+' : '-');
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
