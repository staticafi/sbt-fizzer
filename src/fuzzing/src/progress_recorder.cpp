#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/execution_trace.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>

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
{}


void  progress_recorder::start(std::filesystem::path const&  output_dir_)
{
    output_dir = output_dir_ / "progress_recording";
    std::filesystem::remove_all(output_dir);
    std::filesystem::create_directories(output_dir);
    if (!std::filesystem::is_directory(output_dir))
        throw std::runtime_error("Cannot create directory: " + output_dir.string());
    started = true;
}


void  progress_recorder::stop()
{
    started = false;
    output_dir.clear();
 
    analysis = NONE;
    counter_analysis = 1;
    counter_results = 0;
}


void  progress_recorder::on_analysis_start(ANALYSIS const  a)
{
    if (!is_started())
        return;
    analysis = a;
    if (counter_results != 0)
        ++counter_analysis;
    counter_results = 0;
    num_bytes = 0;
}


void  progress_recorder::on_analysis_stop()
{
    analysis = NONE;
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
        throw std::runtime_error("Cannot create directory: " + output_dir.string());

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

    ostr << "\"num_trace_records\": " << trace.size() << ",\n\"trace_records\": [";

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
