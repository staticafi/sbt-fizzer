#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/execution_trace.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <instrumentation/target_termination.hpp>
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
    , sensitivity{}
    , minimization{}
    , bitshare{}
    , counter_analysis{ 1 }
    , counter_results{ 0 }
{}


void  progress_recorder::start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_)
{
    ASSUMPTION(!is_started());

    output_dir = output_dir_ / "progress_recording";
    std::filesystem::remove_all(output_dir);
    std::filesystem::create_directories(output_dir);
    if (!std::filesystem::is_directory(output_dir))
        throw std::runtime_error("Cannot create directory: " + output_dir.string());

    {
        std::filesystem::path  input_dir{ path_to_client_.parent_path() };
        std::string  executable_name{ path_to_client_.filename().string() };
        std::string  program_name{ executable_name.substr(0, executable_name.find("_sbt-fizzer_target")) };

        if (!copy_file(input_dir, program_name + ".i", "source.c", output_dir, false))
            copy_file(input_dir, program_name + ".c", "source.c", output_dir);
        copy_file(input_dir, program_name + "_instrumented.ll", "source.ll", output_dir);
        copy_file(input_dir, program_name + "_dbg_cond_map.json", "cond_map.json", output_dir);
        copy_file(input_dir, program_name + "_dbg_br_map.json", "br_map.json", output_dir);
    }

    started = true;

    analysis = NONE;
    sensitivity = {};
    minimization = {};
    bitshare = {};
    counter_analysis = 1;
    counter_results = 0;
    num_bytes = 0;
}


void  progress_recorder::stop()
{
    started = false;
    output_dir.clear();
 
    analysis = NONE;
    sensitivity = {};
    minimization = {};
    bitshare = {};
    counter_analysis = 1;
    counter_results = 0;
    num_bytes = 0;
}


void  progress_recorder::on_sensitivity_start(branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    on_analysis_start(SENSITIVITY, sensitivity, node_ptr);
}


void  progress_recorder::on_sensitivity_stop()
{
    if (!is_started())
        return;

    //save_sensitive_bits();
    sensitivity.save();
    on_analysis_stop();
}


void  progress_recorder::on_minimization_start(
        branching_node* const  node_ptr,
        vecu32 const&  bit_translation,
        stdin_bits_pointer const  bits_ptr
        )
{
    if (!is_started())
        return;

    on_analysis_start(MINIMIZATION, minimization, node_ptr);
    minimization.bits_ptr = bits_ptr;
    minimization.bit_translation = bit_translation;
}


void  progress_recorder::on_minimization_gradient_step()
{
    minimization.stage_changes.push_back({
            counter_results,
            (natural_32_bit)minimization.execution_cache_hits.size(),
            minimization_analysis::gradient_descent_state::STEP
            });
}


void  progress_recorder::on_minimization_execution_results_available(
        minimization_analysis::gradient_descent_state::STAGE const stage,
        vecb const&  bits,
        std::size_t const  bits_hash
        )
{
    if (!is_started())
        return;

    auto const  ostr_ptr{ save_default_execution_results() };
    std::ofstream&  ostr{ *ostr_ptr };

    ostr << "\"bits_hash\": " << bits_hash << ",\n"
         << "\"bits\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)bits.size(); i < n; ++i)
    {
        if (i % 8U == 0U) ostr << '\n';
        ostr << (bits.at(i) ? 1 : 0);
        if (i + 1 < n) ostr << ',';
    }

    ostr << "]\n}\n";

    if (minimization.stage_changes.empty()
            || stage != minimization.stage_changes.back().stage
            || (stage != minimization_analysis::gradient_descent_state::PARTIALS &&
                stage != minimization_analysis::gradient_descent_state::PARTIALS_EXTENDED))
        minimization.stage_changes.push_back({ counter_results, 0, stage });
}


void  progress_recorder::on_minimization_execution_results_cache_hit(
        minimization_analysis::gradient_descent_state::STAGE stage,
        std::size_t const  bits_hash
        )
{
    if (!is_started())
        return;

    minimization.execution_cache_hits.push_back({ counter_results, bits_hash });

    if (minimization.stage_changes.empty()
            || stage != minimization.stage_changes.back().stage
            || (stage != minimization_analysis::gradient_descent_state::PARTIALS &&
                stage != minimization_analysis::gradient_descent_state::PARTIALS_EXTENDED))
        minimization.stage_changes.push_back({ counter_results, (natural_32_bit)minimization.execution_cache_hits.size(), stage });
}


void  progress_recorder::on_minimization_stop()
{
    if (!is_started())
        return;

    minimization.save();
    on_analysis_stop();
}


void  progress_recorder::on_bitshare_start(branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    on_analysis_start(BITSHARE, bitshare, node_ptr);
}


void  progress_recorder::on_bitshare_stop()
{
    if (!is_started())
        return;

    bitshare.save();
    on_analysis_stop();
}


void  progress_recorder::on_analysis_start(ANALYSIS const  a, analysis_common_info&  info, branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    ASSUMPTION(node_ptr != nullptr);

    analysis = a;
    if (counter_results != 0)
        ++counter_analysis;
    counter_results = 0;
    num_bytes = 0;

    info.node = node_ptr;
    info.analysis_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
}


void  progress_recorder::on_analysis_stop()
{
    if (!is_started() || analysis == NONE)
        return;

    analysis = NONE;
    sensitivity = {};
    minimization = {};
    bitshare = {};
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

    auto const  ostr_ptr{ save_default_execution_results() };
    std::ofstream&  ostr{ *ostr_ptr };

    vecu8 const&  bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();

    ostr << "\"num_generated_input_bytes\": " << num_bytes << ",\n\"num_obtained_input_bytes\": " << bytes.size() << ",\n"
         << "\"obtained_input_bytes\": [";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)bytes.size(); i < n; ++i)
    {
        if (i % 16U == 0U) ostr << '\n';
        ostr << (natural_32_bit)bytes.at(i);
        if (i + 1 < n) ostr << ',';
    }

    ostr << "]\n}\n";
}


std::unique_ptr<std::ofstream>  progress_recorder::save_default_execution_results()
{
    ++counter_results;

    std::filesystem::path const  record_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
    std::filesystem::create_directories(record_dir);
    if (!std::filesystem::is_directory(record_dir))
        throw std::runtime_error("Cannot create directory: " + record_dir.string());

    std::filesystem::path const  record_pathname = record_dir / (std::to_string(counter_results) + ".json");
    auto  ostr_ptr{ std::make_unique<std::ofstream>(record_pathname.c_str(), std::ios::binary) };
    if (!ostr_ptr->is_open())
        throw std::runtime_error("Cannot open file for writing: " + record_pathname.string());

    std::ofstream&  ostr{ *ostr_ptr }; 

    execution_trace const&  trace = iomodels::iomanager::instance().get_trace();

    ostr << "{\n";

    ostr << "\"trace_termination\": \"";

    switch (iomodels::iomanager::instance().get_termination())
    {
    case instrumentation::target_termination::normal: ostr << "NORMAL"; break;
    case instrumentation::target_termination::crash: ostr << "CRASH"; break;
    case instrumentation::target_termination::boundary_condition_violation: ostr << "BOUNDARY_CONDITION_VIOLATION"; break;
    default: UNREACHABLE(); break;
    }

    ostr << "\",\n\"num_trace_records\": " << trace.size() << ",\n\"trace_records\": [";

    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.size(); i < n; ++i)
    {
        ostr << '\n';
        ostr << trace.at(i).id.id << ',' << trace.at(i).id.context_hash << ','
             << (trace.at(i).direction ? 1 : 0) << ','
             << std::setprecision(std::numeric_limits<branching_function_value_type>::digits10 + 1) << trace.at(i).value;
        if (i + 1 < n) ostr << ',';
    }

    ostr << "],\n";

    return ostr_ptr;
}


std::string const&  progress_recorder::analysis_name(ANALYSIS const a)
{
    static std::string const  names[] { "NONE","SENSITIVITY","MINIMIZATION","BITSHARE" };
    ASSUMPTION((int)a < sizeof(names)/sizeof(names[0]));
    return names[(int)a];
}


void  progress_recorder::analysis_common_info::save() const
{
    if (!std::filesystem::is_directory(analysis_dir))
        return; // No input was generated => the analysis did nothing => no need to save any data.

    std::vector<branching_location_and_direction>  path;
    for (branching_node* n = node->predecessor, *s = node; n != nullptr; s = n, n = n->predecessor)
        path.push_back({ n->id, n->successor_direction(s) });
    std::reverse(path.begin(), path.end());

    std::filesystem::path const  pathname = analysis_dir / "info.json";
    std::ofstream  ostr(pathname.c_str(), std::ios::binary);
    if (!ostr.is_open())
        throw std::runtime_error("Cannot open file for writing: " + pathname.string());
 
    ostr << "{\n";

    {
        auto const pos_old = ostr.tellp();
        save_info(ostr);
        auto const pos_new = ostr.tellp();
        if (pos_new != pos_old)
            ostr << ",\n";
    }

    ostr << "\"node\": [\n";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)path.size(); i < n; ++i)
    {
        ostr << path.at(i).first.id << ',' << path.at(i).first.context_hash << ',' << (path.at(i).second ? 1 : 0);
        if (i + 1 < n) ostr << ',';
        ostr << '\n';
    }
    ostr << "]\n";

    ostr << "}\n";
}


void  progress_recorder::sensitivity_progress_info::save_info(std::ostream&  ostr) const
{
    std::vector<branching_node*>  nodes;
    for (branching_node*  n = node; n != nullptr; n = n->predecessor)
        nodes.push_back(n);
    std::reverse(nodes.begin(), nodes.end());

    ostr << "\"sensitive_bits\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)nodes.size(); i < end; ++i)
    {
        branching_node* const  n = nodes.at(i);
        ostr << '[';
        bool first = true;
        std::vector<natural_32_bit>  indices(n->sensitive_stdin_bits.begin(), n->sensitive_stdin_bits.end());
        std::sort(indices.begin(), indices.end());
        for (natural_32_bit idx : indices)
        {
            if (!first) ostr << ',';
            ostr << idx;
            first = false;
        }
        ostr << ']';
        if (i + 1 < end) ostr << ',';
        ostr << '\n';
    }
    ostr << "]";
}


void  progress_recorder::minimization_progress_info::save_info(std::ostream&  ostr) const
{
    ostr << "\"bit_translation\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bit_translation.size(); i < end; ++i)
    {
        ostr << bit_translation.at(i);
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"all_input_bits\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bits_ptr->size(); i < end; ++i)
    {
        if (i % 8U == 0U) ostr << '\n';
        ostr << (bits_ptr->at(i) ? '1' : '0');
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"stage_changes\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)stage_changes.size(); i < end; ++i)
    {
        ostr << stage_changes.at(i).trace_index << ',' << stage_changes.at(i).cache_hit_index << ",\"";
        switch (stage_changes.at(i).stage)
        {
            case STAGE::TAKE_NEXT_SEED: ostr << "TAKE_NEXT_SEED"; break;
            case STAGE::EXECUTE_SEED: ostr << "EXECUTE_SEED"; break;
            case STAGE::STEP: ostr << "STEP"; break;
            case STAGE::PARTIALS: ostr << "PARTIALS"; break;
            case STAGE::PARTIALS_EXTENDED: ostr << "PARTIALS_EXTENDED"; break;
            default: ostr << "UNKNOWN"; break;
        }
        ostr << '"';
        if (i + 1 < end) ostr << ',';
        ostr << '\n';
    }
    ostr << "],\n\"execution_cache_hits\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)execution_cache_hits.size(); i < end; ++i)
    {
        ostr << execution_cache_hits.at(i).trace_index << ',' << execution_cache_hits.at(i).bits_hash;
        if (i + 1 < end) ostr << ',';
        ostr << '\n';
    }
    ostr << "]";
}


void  progress_recorder::bitshare_progress_info::save_info(std::ostream&  ostr) const
{
}


}
