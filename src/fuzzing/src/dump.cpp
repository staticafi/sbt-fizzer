#include <fuzzing/dump.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/math.hpp>
#include <utility/log.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace  fuzzing {


void  print_fuzzing_configuration(
        std::ostream&  ostr,
        std::string const&  benchmark,
        iomodels::iomanager::configuration const&  ioconfig,
        termination_info const&  terminator
        )
{
    ostr << "Accepted the following configuration:\n"
         << "   Benchmark: " << benchmark << "\n"
         << "   Max executions: " << terminator.max_driver_executions << "\n"
         << "   Max seconds: " << terminator.max_fuzzing_seconds << "\n"
         << "   Max trace length: " << ioconfig.max_trace_length << "\n"
         << "   Max stack size: " << (int)ioconfig.max_stack_size << "\n"
         << "   Max stdin bits: " << ioconfig.max_stdin_bits << "\n"
         << "   stdin model: " << ioconfig.stdin_model_name << "\n"
         << "   stdout model: " << ioconfig.stdout_model_name << "\n"
         ;
    ostr.flush();

    LOG(LSL_INFO,
        "Fuzzing '" << benchmark << ". "
            << "[Max executions: " << terminator.max_driver_executions
            << ", Max seconds: " << terminator.max_fuzzing_seconds
            << ", Max trace length: " << ioconfig.max_trace_length << "\n"
            << ", Max stack size: " << (int)ioconfig.max_stack_size << "\n"
            << ", Max stdin bits: " << ioconfig.max_stdin_bits << "\n"
            << ", stdin model: " << ioconfig.stdin_model_name << "\n"
            << ", stdout model: " << ioconfig.stdout_model_name << "\n"
            << ']');
}


void  print_analysis_outcomes(std::ostream&  ostr, analysis_outcomes const&  results, bool const  dump_traces)
{
    switch (results.termination_type)
    {
    case analysis_outcomes::TERMINATION_TYPE::NORMAL:
        ostr << "Fuzzing terminated normally.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR:
        ostr << "Fuzzing early-terminated due to an internal server error.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::CLIENT_COMMUNICATION_ERROR:
        ostr << "Fuzzing early-terminated due to error in communication with the client.";
        break;
    case analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_ERROR:
        ostr << "Fuzzing early-terminated due to an unclassified error.";
        break;
    }
    ostr << " Details:\n   Termination reason: " << results.termination_message << std::endl;

    ostr << "   Executions performed: " << results.num_executions << '\n'
         << "   Seconds spent: " << results.num_elapsed_seconds << '\n'
         << "   Sensitivity analysis:\n"
         << "       Generated inputs: " << results.sensitivity_statistics.generated_inputs << '\n'
         << "       Max bits: " << results.sensitivity_statistics.max_bits << '\n'
         << "       Start calls: " << results.sensitivity_statistics.start_calls << '\n'
         << "       Stop calls regular: " << results.sensitivity_statistics.stop_calls_regular << '\n'
         << "       Stop calls early: " << results.sensitivity_statistics.stop_calls_early << '\n'
         << "   Minimization analysis:\n"
         << "       Generated inputs: " << results.minimization_statistics.generated_inputs << '\n'
         << "       Max bits: " << results.minimization_statistics.max_bits << '\n'
         << "       Seeds processed: " << results.minimization_statistics.seeds_processed << '\n'
         << "       Gradient steps: " << results.minimization_statistics.gradient_steps << '\n'
         << "       Start calls: " << results.minimization_statistics.start_calls << '\n'
         << "       Stop calls regular: " << results.minimization_statistics.stop_calls_regular << '\n'
         << "       Stop calls early: " << results.minimization_statistics.stop_calls_early << '\n'
         << "   Fuzzer:\n"
         << "       Tree leaves created: " << results.statistics.leaf_nodes_created << '\n'
         << "       Tree leaves destroyed: " << results.statistics.leaf_nodes_destroyed << '\n'
         << "       Tree nodes created: " << results.statistics.nodes_created << '\n'
         << "       Tree nodes destroyed: " << results.statistics.nodes_destroyed << '\n'
         << "       Max tree leaves: " << results.statistics.max_leaf_nodes << '\n'
         << "       Longest tree branch: " << results.statistics.longest_branch << '\n'
         << "       Traces to crash total: " << results.statistics.traces_to_crash_total << '\n'
         << "       Traces to crash recorded: " << results.statistics.traces_to_crash_recorded << '\n'
         ;

    if (results.statistics.leaf_nodes_created != results.statistics.leaf_nodes_destroyed)
        ostr << "   WARNING: The number of created and destroyed leaf nodes differ." << '\n';
    if (results.statistics.nodes_created != results.statistics.nodes_destroyed)
        ostr << "   WARNING: The number of created and destroyed nodes differ => Memory leak!" << '\n';
    if (results.sensitivity_statistics.start_calls != results.sensitivity_statistics.stop_calls_regular + results.sensitivity_statistics.stop_calls_early)
        ostr << "   WARNING: The number of starts does not match to the number of stops in the sensitivity analysis." << '\n';
    if (results.minimization_statistics.start_calls != results.minimization_statistics.stop_calls_regular + results.minimization_statistics.stop_calls_early)
        ostr << "   WARNING: The number of starts does not match to the number of stops in the minimization analysis." << '\n';

    ostr << "   Covered branchings [line]: " << results.covered_branchings.size() << std::endl;
    for (instrumentation::location_id const  id : results.covered_branchings)
        ostr << "      " << id << "\n";

    ostr << "   Uncovered branchings [line, direction]: " << results.uncovered_branchings.size() << std::endl;
    for (auto const&  id_and_branching : results.uncovered_branchings)
        ostr << "      " << id_and_branching.first << (id_and_branching.second ? '+' : '-') << "\n";

    ostr << "   Generated tests: " << results.execution_records.size() << std::endl;
    if (dump_traces)
        for (execution_record const&  record : results.execution_records)
        {
            ostr << "   ******************************************\n";
            print_execution_record(ostr, record, true, "   ");
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
            sstr << id_and_branching.first << (id_and_branching.second ? '+' : '-');
        LOG(LSL_INFO, "Fuzzing did not cover these branchings: " << sstr.str());
    }
}


void  print_execution_record(
        std::ostream&  ostr,
        execution_record const&  record,
        bool  dump_chunks,
        std::string const&  shift
        )
{
    vecu8  byte_values;
    bits_to_bytes(record.stdin_bits, byte_values);

    vecu64  chunk_values;
    for (natural_32_bit  k = 0U, i = 0U, n = (natural_32_bit)record.stdin_bit_counts.size(); i < n; ++i)
    {
        ASSUMPTION(record.stdin_bit_counts.at(i) <= 8U * sizeof(chunk_values.back()));
        chunk_values.push_back(0U);
        for (natural_8_bit  j = 0U, m = record.stdin_bit_counts.at(i) / 8U; j < m; ++j)
            *(((natural_8_bit*)&chunk_values.back()) + j) = byte_values.at(k + j);
        k += record.stdin_bit_counts.at(i) / 8U;
    }

    ostr << shift << "flags [discovery, coverage, crash]:\n" << shift << shift 
         << ((record.flags & execution_record::BRANCH_DISCOVERED) != 0) << ", "
         << ((record.flags & execution_record::BRANCH_COVERED) != 0) << ", "
         << ((record.flags & execution_record::EXECUTION_CRASHES) != 0) << '\n'
         ;

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
            if (i != 0U) ostr << ", ";
            if (i % 8U == 0U) ostr << '\n' << shift << shift;
            ostr << std::dec << (natural_32_bit)record.stdin_bit_counts.at(i) / 8U << ':'
                 << std::dec << (natural_32_bit)chunk_values.at(i);
        }
    }

    ostr << '\n' << shift << "branchings: " << record.path.size();
    for (natural_32_bit  i = 0U, n = (natural_32_bit)record.path.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n' << shift << shift;
        ostr << std::dec << record.path.at(i).first << (record.path.at(i).second ? '+' : '-');
    }

    ostr << std::endl;
}

void  save_execution_records_to_directory(
        std::filesystem::path const&  output_dir,
        std::vector<execution_record> const&  records,
        bool  dump_chunks,
        std::string const&  test_name_prefix
        )
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)records.size(); i < n; ++i)
    {
        std::filesystem::path const  test_file_path = output_dir / (test_name_prefix + "_" + std::to_string(i + 1U) + ".et");
        std::ofstream  ostr(test_file_path.c_str(), std::ios::binary);
        print_execution_record(ostr, records.at(i), dump_chunks, "   ");
    }
}


void  save_debug_data_to_directory(
        std::filesystem::path const&  output_dir,
        std::string const&  name_prefix,
        std::unordered_map<std::string, std::string> const&  data
        )
{
    for (auto const&  suffix_and_value : data)
    {
        std::filesystem::path const  debug_file_path = output_dir / (name_prefix + suffix_and_value.first);
        std::ofstream  ostr(debug_file_path.c_str(), std::ios::binary);
        ostr << suffix_and_value.second;
    }
}


}
