#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/execution_trace.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <vector>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>


static bool  copy_file(
        std::filesystem::path const&  input_dir,
        std::string const&  src_file_name,
        std::string const&  dst_file_name,
        std::filesystem::path const&  output_dir,
        bool const  throw_on_failure = true
        )
{
    if (!std::filesystem::is_regular_file(input_dir / src_file_name))
    {
        if (throw_on_failure)
            throw std::runtime_error(
                        "Cannot copy file '" + (input_dir / src_file_name).string() +
                        "' to file '" + (output_dir / dst_file_name).string() + "'."
                        );
        return false;
    }
    std::filesystem::copy_file(input_dir / src_file_name, output_dir / dst_file_name);
    return true;
}


namespace fuzzing {


progress_recorder& progress_recorder::instance()
{
    static progress_recorder rec;
    return rec;
}


progress_recorder::progress_recorder()
    : started{ false }
    , output_dir{}

    , analysis{ NONE }
    , counter_analysis{ 1 }
    , counter_results{ 0 }
    , node{ nullptr }
    , node_saved{ false }
{}


void  progress_recorder::start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_)
{
    output_dir = output_dir_ / "progress_recording";
    std::filesystem::remove_all(output_dir);
    std::filesystem::create_directories(output_dir);
    if (!std::filesystem::is_directory(output_dir))
        throw std::runtime_error("Cannot create directory: " + output_dir.string());

    {
        std::filesystem::path  input_dir{ path_to_client_.parent_path() };
        std::string  program_name{ path_to_client_.filename().replace_extension("") };

        if (!copy_file(input_dir, program_name + ".i", "source.c", output_dir, false))
            copy_file(input_dir, program_name + ".c", "source.c", output_dir);
        copy_file(input_dir, program_name + ".ll", "source.ll", output_dir);
        copy_file(input_dir, program_name + "_dbg_cond_map.json", "cond_map.json", output_dir);
        copy_file(input_dir, program_name + "_dbg_br_map.json", "br_map.json", output_dir);
    }

    started = true;

    analysis = NONE;
    counter_analysis = 1;
    counter_results = 0;
    node = nullptr;
    node_saved = false;
}


void  progress_recorder::stop()
{
    started = false;
    output_dir.clear();
 
    analysis = NONE;
    counter_analysis = 1;
    counter_results = 0;
    node = nullptr;
}


void  progress_recorder::on_analysis_start(ANALYSIS const  a, branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    ASSUMPTION(node_ptr != nullptr);

    analysis = a;
    if (counter_results != 0)
        ++counter_analysis;
    counter_results = 0;
    num_bytes = 0;
    node = node_ptr;
}


void  progress_recorder::on_analysis_stop()
{
    analysis = NONE;
    node = nullptr;
    node_saved = false;
}


void  progress_recorder::save_sensitive_bits()
{
    if (!is_started())
        return;

    ASSUMPTION(analysis == SENSITIVITY && node != nullptr);

    std::filesystem::path const  record_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
    if (!std::filesystem::is_directory(record_dir))
        throw std::runtime_error("The directory of the analysis does not exist: " + record_dir.string());

    std::filesystem::path const  bits_pathname = record_dir / "sensitive_bits.json";
    std::ofstream  ostr(bits_pathname.c_str(), std::ios::binary);
    if (!ostr.is_open())
        throw std::runtime_error("Cannot open file for writing: " + bits_pathname.string());

    std::vector<branching_node*>  nodes;
    for (branching_node*  n = node; n != nullptr; n = n->predecessor)
        nodes.push_back(n);
    std::reverse(nodes.begin(), nodes.end());

    ostr << "[\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)nodes.size(); i < end; ++i)
    {
        branching_node* const  n = nodes.at(i);
        ostr << n->sensitive_stdin_bits.size();
        if (i + 1 < end) ostr << ',';
        ostr << '\n';
    }
    ostr << "]\n";
}


void  progress_recorder::on_input_generated()
{
    if (!is_started())
        return;
    num_bytes = (natural_32_bit)iomodels::iomanager::instance().get_stdin()->get_bytes().size();
}


void  progress_recorder::on_execution_results_available()
{
    if (!is_started())
        return;

    ++counter_results;

    std::filesystem::path const  record_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
    std::filesystem::create_directories(record_dir);
    if (!std::filesystem::is_directory(record_dir))
        throw std::runtime_error("Cannot create directory: " + record_dir.string());

    if (node != nullptr && !node_saved)
    {
        std::vector<branching_location_and_direction>  path;
        for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
            path.push_back({ n->id, n->successor_direction(s) });
        std::reverse(path.begin(), path.end());

        std::filesystem::path const  node_pathname = record_dir / "node.json";
        std::ofstream  ostr(node_pathname.c_str(), std::ios::binary);
        if (!ostr.is_open())
            throw std::runtime_error("Cannot open file for writing: " + node_pathname.string());
        ostr << "[\n";
        for (natural_32_bit  i = 0U, n = (natural_32_bit)path.size(); i < n; ++i)
        {
            ostr << path.at(i).first.id << ',' << path.at(i).first.context_hash << ',' << (path.at(i).second ? 1 : 0);
            if (i + 1 < n) ostr << ',';
            ostr << '\n';
        }
        ostr << "]\n";

        node_saved = true;
    }

    std::filesystem::path const  record_pathname = record_dir / (std::to_string(counter_results) + ".json");
    std::ofstream  ostr(record_pathname.c_str(), std::ios::binary);
    if (!ostr.is_open())
        throw std::runtime_error("Cannot open file for writing: " + record_pathname.string());

    vecu8 const&  bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();

    ostr << "{\n\"num_generated_input_bytes\": " << num_bytes << ",\n\"num_obtained_input_bytes\": " << bytes.size() << ",\n"
         << "\"obtained_input_bytes\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)bytes.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n';
        ostr << (natural_32_bit)bytes.at(i);
        if (i + 1 < n) ostr << ", ";
    }

    ostr << "],\n";

    execution_trace const&  trace = iomodels::iomanager::instance().get_trace();

    ostr << "\"trace_termination\": \"";

    switch (iomodels::iomanager::instance().get_termination())
    {
    case iomodels::iomanager::NORMAL: ostr << "NORMAL"; break;
    case iomodels::iomanager::CRASH: ostr << "CRASH"; break;
    case iomodels::iomanager::BOUNDARY_CONDITION_VIOLATION: ostr << "BOUNDARY_CONDITION_VIOLATION"; break;
    default: UNREACHABLE(); break;
    }

    ostr << "\",\n\"num_trace_records\": " << trace.size() << ",\n\"trace_records\": [";

    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.size(); i < n; ++i)
    {
        ostr << '\n';
        ostr << trace.at(i).id.id << ',' << trace.at(i).id.context_hash << ','
             << (trace.at(i).direction ? 1 : 0) << ','
             << trace.at(i).value;
        if (i + 1 < n) ostr << ',';
    }

    ostr << "]\n}\n";
}


std::string const&  progress_recorder::analysis_name(ANALYSIS const a)
{
    static std::string const  names[] { "NONE","SENSITIVITY","MINIMIZATION","BITSHARE" };
    ASSUMPTION((int)a < sizeof(names)/sizeof(names[0]));
    return names[(int)a];
}


}
