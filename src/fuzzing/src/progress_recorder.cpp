#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/execution_trace.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
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
    , program_name{}

    , analysis{ ANALYSIS::NONE }
    , bitshare{}
    , local_search{}
    , bitflip{}
    , taint_request{}
    , taint_response{}
    , counter_analysis{ 1 }
    , counter_results{ 0 }

    , num_bytes{ 0 }
    , leaf{ nullptr }

    , post_data{}
{}


void  progress_recorder::start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_)
{
    ASSUMPTION(!is_started());

    output_dir = output_dir_ / "progress_recording";
    std::filesystem::remove_all(output_dir);
    std::filesystem::create_directories(output_dir);
    if (!std::filesystem::is_directory(output_dir))
        throw std::runtime_error("Cannot create directory: " + output_dir.string());

    std::filesystem::path const  input_dir{ path_to_client_.parent_path() };
    std::string const  executable_name{ path_to_client_.filename().string() };

    program_name = executable_name.substr(0, executable_name.find("_sbt-fizzer_target"));

    if (!copy_file(input_dir, program_name + ".i", "source.c", output_dir, false))
        copy_file(input_dir, program_name + ".c", "source.c", output_dir);
    copy_file(input_dir, program_name + "_instrumented.ll", "source.ll", output_dir);
    copy_file(input_dir, program_name + "_dbg_cond_map.json", "cond_map.json", output_dir);
    copy_file(input_dir, program_name + "_dbg_br_map.json", "br_map.json", output_dir);

    started = true;

    analysis = ANALYSIS::NONE;
    bitshare = {};
    local_search = {};
    bitflip = {};
    taint_request = {};
    taint_response = {};
    counter_analysis = 1;
    counter_results = 0;

    num_bytes = 0;
    leaf = nullptr;

    post_data.clear();
}


void  progress_recorder::stop()
{
    if (!is_started())
        return;

    std::filesystem::path const  input_dir{ output_dir.parent_path() };

    copy_file(input_dir, program_name + "_config.json", "config.json", output_dir);
    copy_file(input_dir, program_name + "_outcomes.json", "outcomes.json", output_dir);

    for (natural_32_bit  i = 1U; true; ++i)
        if (!copy_file(input_dir, program_name + "_test_" + std::to_string(i) + ".json",
                       "test_" + std::to_string(i) + ".json", output_dir, false))
            break;

    if (std::filesystem::is_directory(input_dir / "test-suite"))
        for (natural_32_bit  i = 1U; true; ++i)
            if (!copy_file(input_dir / "test-suite", program_name + "_test_" + std::to_string(i) + ".xml",
                        "test_" + std::to_string(i) + ".xml", output_dir, false))
                break;

    started = false;

    output_dir.clear();
    program_name.clear();
 
    analysis = ANALYSIS::NONE;
    bitshare = {};
    local_search = {};
    bitflip = {};
    taint_request = {};
    taint_response = {};
    counter_analysis = 1;
    counter_results = 0;

    num_bytes = 0;
    leaf = nullptr;

    post_data.clear();
}


void  progress_recorder::on_bitshare_start(branching_node const* const  node_ptr, START const  attribute)
{
    if (!is_started())
        return;

    bitshare.start_type = attribute;
    on_analysis_start(ANALYSIS::BITSHARE, bitshare, node_ptr);
}


void  progress_recorder::on_bitshare_stop(STOP const  attribute)
{
    if (!is_started())
        return;
    if (bitshare.start_type == START::NONE)
        return;
    ASSUMPTION(analysis == ANALYSIS::BITSHARE);

    bitshare.stop_type = attribute;
    bitshare.save();
    on_analysis_stop();
}


void  progress_recorder::on_local_search_start(branching_node const* const  node_ptr, START const  attribute)
{
    if (!is_started())
        return;

    local_search.start_type = attribute;
    on_analysis_start(ANALYSIS::LOCAL_SEARCH, local_search, node_ptr);
}


void  progress_recorder::on_local_search_stop(STOP const  attribute)
{
    if (!is_started())
        return;
    if (local_search.start_type == START::NONE)
        return;
    ASSUMPTION(analysis == ANALYSIS::LOCAL_SEARCH);

    local_search.stop_type = attribute;
    local_search.save();
    on_analysis_stop();
}


void  progress_recorder::on_bitflip_start(branching_node const* const  node_ptr, START const  attribute)
{
    if (!is_started())
        return;

    bitflip.start_type = attribute;
    on_analysis_start(ANALYSIS::BITFLIP, bitflip, node_ptr);
}


void  progress_recorder::on_bitflip_stop(STOP const  attribute)
{
    if (!is_started())
        return;
    if (bitflip.start_type == START::NONE)
        return;
    ASSUMPTION(analysis == ANALYSIS::BITFLIP);

    bitflip.stop_type = attribute;
    bitflip.save();
    on_analysis_stop();
}


void  progress_recorder::on_taint_request_start(branching_node const* const  node_ptr, START const  attribute)
{
    if (!is_started())
        return;

    taint_request.start_type = attribute;
    on_analysis_start(ANALYSIS::TAINT_REQUEST, taint_request, node_ptr);
}


void  progress_recorder::on_taint_request_stop(STOP const  attribute)
{
    if (!is_started())
        return;
    if (taint_request.start_type == START::NONE)
        return;
    ASSUMPTION(analysis == ANALYSIS::TAINT_REQUEST);

    taint_request.stop_type = attribute;
    taint_request.save();
    on_analysis_stop();
}


void  progress_recorder::on_taint_response_start(branching_node const* const  node_ptr, START const  attribute)
{
    if (!is_started())
        return;

    taint_response.start_type = attribute;
    on_analysis_start(ANALYSIS::TAINT_RESPONSE, taint_response, node_ptr);
}


void  progress_recorder::on_taint_response_stop(STOP const  attribute)
{
    if (!is_started())
        return;
    if (taint_response.start_type == START::NONE)
        return;
    ASSUMPTION(analysis == ANALYSIS::TAINT_RESPONSE);

    taint_response.stop_type = attribute;
    taint_response.save();
    on_analysis_stop();
}



void  progress_recorder::on_analysis_start(ANALYSIS const  analysis_, analysis_common_info&  info, branching_node const* const  node_ptr)
{
    if (!is_started())
        return;

    flush_post_data();

    analysis = analysis_;
    ++counter_analysis;
    counter_results = 0;

    num_bytes = 0;
    leaf = nullptr;

    info.node = node_ptr;
    info.analysis_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
    std::filesystem::create_directories(info.analysis_dir);
    if (!std::filesystem::is_directory(info.analysis_dir))
        throw std::runtime_error("Cannot create directory: " + info.analysis_dir.string());

    post_data.set_output_dir(info.analysis_dir);
}


void  progress_recorder::on_analysis_stop()
{
    if (!is_started() || analysis == ANALYSIS::NONE)
        return;

    analysis = ANALYSIS::NONE;
    bitshare = {};
    local_search = {};
    bitflip = {};
    taint_request = {};
    taint_response = {};
}


void  progress_recorder::on_input_generated()
{
    if (!is_started())
        return;
    num_bytes = (natural_32_bit)iomodels::iomanager::instance().get_stdin()->get_bytes().size();
}


void  progress_recorder::on_trace_mapped_to_tree(branching_node const* const  leaf_)
{
    if (!is_started())
        return;
    leaf = leaf_;
}


void  progress_recorder::on_execution_results_available()
{
    if (!is_started())
        return;

    TMPROF_BLOCK();

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
    TMPROF_BLOCK();

    ++counter_results;

    std::filesystem::path const  record_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));
    std::filesystem::create_directories(record_dir);
    if (!std::filesystem::is_directory(record_dir))
        throw std::runtime_error("Cannot create directory: " + record_dir.string());

    std::filesystem::path const  record_pathname = record_dir / (std::to_string(counter_results) + ".json");
    auto  ostr_ptr{ std::make_unique<std::ofstream>(record_pathname.c_str(), std::ios::binary) };
    if (!ostr_ptr->is_open())
        throw std::runtime_error("Cannot open file for writing: " + record_pathname.string());

    if (post_data.output_dir.empty())
        post_data.output_dir = record_dir;

    std::ofstream&  ostr{ *ostr_ptr }; 

    execution_trace const&  trace = iomodels::iomanager::instance().get_trace();

    std::vector<branching_node::guid_type>  node_guids;
    for (branching_node const* n = leaf; n != nullptr; n = n->get_predecessor())
        node_guids.push_back(n->guid());
    std::reverse(node_guids.begin(), node_guids.end());

    INVARIANT(trace.size() == node_guids.size());

    ostr << "{\n";

    ostr << "\"trace_termination\": \"";

    switch (iomodels::iomanager::instance().get_termination())
    {
    case instrumentation::target_termination::normal: ostr << "NORMAL"; break;
    case instrumentation::target_termination::crash: ostr << "CRASH"; break;
    case instrumentation::target_termination::timeout: ostr << "TIMEOUT"; break;
    case instrumentation::target_termination::boundary_condition_violation: ostr << "BOUNDARY_CONDITION_VIOLATION"; break;
    case instrumentation::target_termination::medium_overflow: ostr << "MEDIUM_OVERFLOW"; break;
    default: UNREACHABLE(); break;
    }

    ostr << "\",\n\"num_trace_records\": " << trace.size() << ",\n\"trace_records\": [";

    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.size(); i < n; ++i)
    {
        branching_function_value_type const  value =
                std::isfinite(trace.at(i).value) ? trace.at(i).value : std::numeric_limits<branching_function_value_type>::max();
        ostr << '\n';
        ostr << trace.at(i).id.id << ',' << trace.at(i).id.context_hash << ','
             << (trace.at(i).direction ? 1 : 0) << ','
             << trace.at(i).num_input_bytes << ','
             << std::setprecision(std::numeric_limits<branching_function_value_type>::digits10 + 1) << value << ','
             << node_guids.at(i);
        if (i + 1 < n) ostr << ',';
    }

    ostr << "],\n";

    return ostr_ptr;
}


std::string const&  progress_recorder::analysis_name(ANALYSIS const a)
{
    static std::string const  names[] { "NONE","BITSHARE","LOCAL_SEARCH","BITFLIP","TAINT_REQ","TAINT_RES" };
    ASSUMPTION((int)a < sizeof(names)/sizeof(names[0]));
    return names[(int)a];
}


void  progress_recorder::analysis_common_info::save() const
{
    TMPROF_BLOCK();

    if (!std::filesystem::is_directory(analysis_dir))
        throw std::runtime_error("Analysis directory does not exist: " + analysis_dir.string());

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

    ostr << "\"node_guid\": " << (node == nullptr ? 0U : node->guid()) << ",\n";

    ostr << "\"start_attribute\": ";
    switch (start_type)
    {
        case START::REGULAR: ostr << "\"REGULAR\""; break;
        case START::RESUMED: ostr << "\"RESUMED\""; break;
        default: UNREACHABLE(); break;
    }
    ostr << ",\n\"stop_attribute\": ";
    switch (stop_type)
    {
        case STOP::INSTANT: ostr << "\"INSTANT\""; break;
        case STOP::EARLY: ostr << "\"EARLY\""; break;
        case STOP::REGULAR: ostr << "\"REGULAR\""; break;
        case STOP::INTERRUPTED: ostr << "\"INTERRUPTED\""; break;
        default: UNREACHABLE(); break;
    }
    ostr << ",\n\"num_coverage_failure_resets\": " << get_num_coverage_failure_resets() << '\n';

    ostr << "}\n";
}


void  progress_recorder::bitshare_progress_info::save_info(std::ostream&  ostr) const
{
}


void  progress_recorder::local_search_progress_info::save_info(std::ostream&  ostr) const
{
}


void  progress_recorder::bitflip_progress_info::save_info(std::ostream&  ostr) const
{
}


void  progress_recorder::taint_request_progress_info::save_info(std::ostream&  ostr) const
{
}


void  progress_recorder::taint_response_progress_info::save_info(std::ostream&  ostr) const
{
    std::vector<branching_node const*>  nodes;
    for (branching_node const*  n = node; n != nullptr; n = n->get_predecessor())
        nodes.push_back(n);
    std::reverse(nodes.begin(), nodes.end());

    ostr << "\"sensitive_bits\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)nodes.size(); i < end; ++i)
    {
        branching_node const* const  n = nodes.at(i);
        ostr << '[';
        bool first = true;
        std::vector<natural_32_bit>  indices(n->get_sensitive_stdin_bits().begin(), n->get_sensitive_stdin_bits().end());
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


void  progress_recorder::on_strategy_turn_primary_loop_head()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::PRIMARY_LOOP_HEAD);
}


void  progress_recorder::on_strategy_turn_primary_sensitive()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::PRIMARY_SENSITIVE);
}


void  progress_recorder::on_strategy_turn_primary_untouched()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::PRIMARY_UNTOUCHED);
}


void  progress_recorder::on_strategy_turn_primary_iid_twins()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::PRIMARY_IID_TWINS);
}


void  progress_recorder::on_strategy_turn_monte_carlo()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::MONTE_CARLO);
}


void  progress_recorder::on_strategy_turn_monte_carlo_backward()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::STRATEGY::MONTE_CARLO_BACKWARD);
}


void  progress_recorder::on_post_node_closed(branching_node const* const  node)
{
    if (!is_started())
        return;
    post_data.on_node_closed(node);
}


void  progress_recorder::flush_post_data()
{
    if (!is_started())
        return;
    if (!post_data.empty() && std::filesystem::is_directory(post_data.output_dir))
        post_data.save();
    post_data.clear();
}


progress_recorder::post_analysis_data::post_analysis_data()
    : output_dir{}
    , strategy{ STRATEGY::NONE }
    , closed_node_guids{}
{}


void  progress_recorder::post_analysis_data::on_strategy_changed(STRATEGY const  strategy_)
{
   strategy = strategy_; 
}


void  progress_recorder::post_analysis_data::on_node_closed(branching_node const* const  node)
{
   closed_node_guids.insert(node->guid()); 
}


void  progress_recorder::post_analysis_data::set_output_dir(std::filesystem::path const&  dir)
{
    output_dir = dir;
}


void  progress_recorder::post_analysis_data::clear()
{
    output_dir.clear();
    strategy = STRATEGY::NONE;
    closed_node_guids.clear();
}


bool  progress_recorder::post_analysis_data::empty() const
{
    return strategy == STRATEGY::NONE && closed_node_guids.empty();
}


void  progress_recorder::post_analysis_data::save() const
{
    TMPROF_BLOCK();

    std::filesystem::path const  record_pathname = output_dir / "post.json";
    std::ofstream  ostr{ record_pathname.c_str(), std::ios::binary };
    if (!ostr.is_open())
        throw std::runtime_error("Cannot open file for writing: " + record_pathname.string());
    ostr << "{\n";

    ostr << "\"strategy\": \"";
    switch (strategy)
    {
        case STRATEGY::NONE: ostr << "NONE"; break;
        case STRATEGY::PRIMARY_LOOP_HEAD: ostr << "PRIMARY_LOOP_HEAD"; break;
        case STRATEGY::PRIMARY_SENSITIVE: ostr << "PRIMARY_SENSITIVE"; break;
        case STRATEGY::PRIMARY_UNTOUCHED: ostr << "PRIMARY_UNTOUCHED"; break;
        case STRATEGY::PRIMARY_IID_TWINS: ostr << "PRIMARY_IID_TWINS"; break;
        case STRATEGY::MONTE_CARLO: ostr << "MONTE_CARLO"; break;
        case STRATEGY::MONTE_CARLO_BACKWARD: ostr << "MONTE_CARLO_BACKWARD"; break;
        default: UNREACHABLE(); break;
    }
    ostr << "\",\n\"closed_node_guids\": [\n";
    for (auto  it = closed_node_guids.begin(); it != closed_node_guids.end(); ++it)
    {
        ostr << *it;
        if (std::next(it) != closed_node_guids.end()) ostr << ",\n";
    }
    ostr << "]\n";

    ostr << "}\n";
}


}
