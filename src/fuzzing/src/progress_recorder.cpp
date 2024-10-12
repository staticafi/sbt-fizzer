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

    , analysis{ NONE }
    , sensitivity{}
    , typed_minimization{}
    , minimization{}
    , bitshare{}
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

    analysis = NONE;
    sensitivity = {};
    typed_minimization = {};
    minimization = {};
    bitshare = {};
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
 
    analysis = NONE;
    sensitivity = {};
    typed_minimization = {};
    minimization = {};
    bitshare = {};
    counter_analysis = 1;
    counter_results = 0;

    num_bytes = 0;
    leaf = nullptr;

    post_data.clear();
}


void  progress_recorder::on_sensitivity_start(branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    on_analysis_start(SENSITIVITY, sensitivity, node_ptr);
}


void  progress_recorder::on_sensitivity_stop(STOP_ATTRIBUTE const  attribute)
{
    if (!is_started())
        return;

    //save_sensitive_bits();
    sensitivity.stop_attribute = attribute;
    sensitivity.save();
    on_analysis_stop();
}


void  progress_recorder::on_typed_minimization_start(
        branching_node* const  node_ptr,
        std::vector<typed_minimization_analysis::mapping_to_input_bits> const&  from_variables_to_input,
        std::vector<type_of_input_bits> const& types_of_variables,
        stdin_bits_and_types_pointer const  bits_and_types
        )
{
    if (!is_started())
        return;

    on_analysis_start(TYPED_MINIMIZATION, typed_minimization, node_ptr);
    typed_minimization.bits_and_types = bits_and_types;
    typed_minimization.from_variables_to_input = from_variables_to_input;
    typed_minimization.types_of_variables = types_of_variables;
}


void  progress_recorder::on_typed_minimization_execution_results_available(
        typed_minimization_analysis::PROGRESS_STAGE const  progress_stage,
        std::vector<typed_minimization_analysis::value_of_variable> const&  variable_values,
        branching_function_value_type const  function_value,
        std::size_t const  variables_hash
        )
{
    if (!is_started())
        return;

    TMPROF_BLOCK();

    auto const  ostr_ptr{ save_default_execution_results() };
    std::ofstream&  ostr{ *ostr_ptr };

    ostr << "\"progress_stage\": \"";
    switch (progress_stage)
    {
        case typed_minimization_analysis::SEED: ostr << "SEED"; break;
        case typed_minimization_analysis::PARTIALS: ostr << "PARTIALS"; break;
        case typed_minimization_analysis::STEP: ostr << "STEP"; break;
    }
    ostr << "\",\n"
         << "\"variables_hash\": " << variables_hash << ",\n"
         << "\"variable_values\": [\n";
    for (natural_32_bit  i = 0U, n = (natural_32_bit)variable_values.size(); i < n; ++i)
    {
        switch (typed_minimization.types_of_variables.at(i))
        {
            case type_of_input_bits::BOOLEAN: ostr << variable_values.at(i).value_boolean; break;
            case type_of_input_bits::UINT8: ostr << (natural_32_bit)variable_values.at(i).value_uint8; break;
            case type_of_input_bits::SINT8: ostr << (integer_32_bit)variable_values.at(i).value_sint8; break;
            case type_of_input_bits::UINT16: ostr << variable_values.at(i).value_uint16; break;
            case type_of_input_bits::SINT16: ostr << variable_values.at(i).value_sint16; break;
            case type_of_input_bits::UINT32: ostr << variable_values.at(i).value_uint32; break;
            case type_of_input_bits::SINT32: ostr << variable_values.at(i).value_sint32; break;
            case type_of_input_bits::UINT64: ostr << variable_values.at(i).value_uint64; break;
            case type_of_input_bits::SINT64: ostr << variable_values.at(i).value_sint64; break;
            case type_of_input_bits::FLOAT32: ostr << variable_values.at(i).value_float32; break;
            case type_of_input_bits::FLOAT64: ostr << variable_values.at(i).value_float64; break;
            default: { UNREACHABLE(); }
        }
        if (i + 1 < n) ostr << ",\n";
    }
    ostr << "],\n\"function_value\": ";
    if (std::isfinite(function_value))
        ostr << function_value;
    else
        ostr << "\"INFINITY\"";

    ostr << "\n}\n";
}


void  progress_recorder::on_typed_minimization_execution_results_cache_hit(
        typed_minimization_analysis::PROGRESS_STAGE  progress_stage,
        std::size_t  variables_hash
        )
{
    if (!is_started())
        return;

    typed_minimization.execution_cache_hits.push_back({ counter_results, variables_hash, progress_stage });
}


void  progress_recorder::on_typed_minimization_stop(STOP_ATTRIBUTE const  attribute)
{
    if (!is_started())
        return;

    typed_minimization.stop_attribute = attribute;
    typed_minimization.save();
    on_analysis_stop();
}


void  progress_recorder::on_minimization_start(
        branching_node* const  node_ptr,
        vecu32 const&  bit_translation,
        stdin_bits_and_types_pointer const  bits_and_types
        )
{
    if (!is_started())
        return;

    on_analysis_start(MINIMIZATION, minimization, node_ptr);
    minimization.bits_and_types = bits_and_types;
    minimization.bit_translation = bit_translation;
}


void  progress_recorder::on_minimization_gradient_step()
{
    if (!is_started())
        return;

    minimization.stage_changes.push_back({
            std::numeric_limits<integer_32_bit>::max(),
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

    TMPROF_BLOCK();

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

    for (auto  it = minimization.stage_changes.rbegin();
            it != minimization.stage_changes.rend() && it->index == std::numeric_limits<integer_32_bit>::max();
            ++it)
        it->index = (integer_32_bit)counter_results;
    if (minimization.stage_changes.empty()
            || stage != minimization.stage_changes.back().stage
            || (stage != minimization_analysis::gradient_descent_state::PARTIALS &&
                stage != minimization_analysis::gradient_descent_state::PARTIALS_EXTENDED))
        minimization.stage_changes.push_back({ (integer_32_bit)counter_results, stage });
}


void  progress_recorder::on_minimization_execution_results_cache_hit(
        minimization_analysis::gradient_descent_state::STAGE stage,
        std::size_t const  bits_hash
        )
{
    if (!is_started())
        return;

    for (auto  it = minimization.stage_changes.rbegin();
            it != minimization.stage_changes.rend() && it->index == std::numeric_limits<integer_32_bit>::max();
            ++it)
        it->index = -(integer_32_bit)minimization.execution_cache_hits.size();
    if (minimization.stage_changes.empty()
            || stage != minimization.stage_changes.back().stage
            || (stage != minimization_analysis::gradient_descent_state::PARTIALS &&
                stage != minimization_analysis::gradient_descent_state::PARTIALS_EXTENDED))
        minimization.stage_changes.push_back({ -(integer_32_bit)minimization.execution_cache_hits.size(), stage });

    minimization.execution_cache_hits.push_back({ counter_results, bits_hash });
}


void  progress_recorder::on_minimization_stop(STOP_ATTRIBUTE const  attribute)
{
    if (!is_started())
        return;

    minimization.stop_attribute = attribute;
    minimization.save();
    on_analysis_stop();
}


void  progress_recorder::on_bitshare_start(branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    on_analysis_start(BITSHARE, bitshare, node_ptr);
}


void  progress_recorder::on_bitshare_stop(STOP_ATTRIBUTE const  attribute)
{
    if (!is_started())
        return;

    bitshare.stop_attribute = attribute;
    bitshare.save();
    on_analysis_stop();
}


void  progress_recorder::on_analysis_start(ANALYSIS const  a, analysis_common_info&  info, branching_node* const  node_ptr)
{
    if (!is_started())
        return;

    flush_post_data();

    ASSUMPTION(node_ptr != nullptr);

    analysis = a;
    if (counter_results != 0)
        ++counter_analysis;
    counter_results = 0;

    num_bytes = 0;
    leaf = nullptr;

    info.node = node_ptr;
    info.analysis_dir = output_dir / (std::to_string(counter_analysis) + '_' + analysis_name(analysis));

    post_data.set_output_dir(info.analysis_dir);
}


void  progress_recorder::on_analysis_stop()
{
    if (!is_started() || analysis == NONE)
        return;

    analysis = NONE;
    sensitivity = {};
    typed_minimization = {};
    minimization = {};
    bitshare = {};
}


void  progress_recorder::on_input_generated()
{
    if (!is_started())
        return;
    num_bytes = (natural_32_bit)iomodels::iomanager::instance().get_stdin()->get_bytes().size();
}


void  progress_recorder::on_trace_mapped_to_tree(branching_node* const  leaf_)
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
    for (branching_node* n = leaf; n != nullptr; n = n->get_predecessor())
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
    static std::string const  names[] { "NONE","SENSITIVITY","TYPED_MINIMIZATION","MINIMIZATION","BITSHARE" };
    ASSUMPTION((int)a < sizeof(names)/sizeof(names[0]));
    return names[(int)a];
}


void  progress_recorder::analysis_common_info::save() const
{
    TMPROF_BLOCK();

    if (!std::filesystem::is_directory(analysis_dir))
        return; // No input was generated => the analysis did nothing => no need to save any data.

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

    ostr << "\"node_guid\": " << node->guid() << ",\n";

    ostr << "\"stop_attribute\": ";
    switch (stop_attribute)
    {
        case INSTANT: ostr << "\"INSTANT\""; break;
        case EARLY: ostr << "\"EARLY\""; break;
        case REGULAR: ostr << "\"REGULAR\""; break;
        default: UNREACHABLE(); break;
    }
    ostr << ",\n\"num_coverage_failure_resets\": " << get_num_coverage_failure_resets() << '\n';

    ostr << "}\n";
}


natural_32_bit  progress_recorder::sensitivity_progress_info::get_num_coverage_failure_resets() const
{
    natural_32_bit  max_num_coverage_failure_resets{ 0U };
    for (branching_node*  n = node; n != nullptr; n = n->get_predecessor())
        if (max_num_coverage_failure_resets < n->get_num_coverage_failure_resets())
            max_num_coverage_failure_resets = n->get_num_coverage_failure_resets();
    return max_num_coverage_failure_resets;
}


void  progress_recorder::sensitivity_progress_info::save_info(std::ostream&  ostr) const
{
    TMPROF_BLOCK();

    std::vector<branching_node*>  nodes;
    for (branching_node*  n = node; n != nullptr; n = n->get_predecessor())
        nodes.push_back(n);
    std::reverse(nodes.begin(), nodes.end());

    ostr << "\"sensitive_bits\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)nodes.size(); i < end; ++i)
    {
        branching_node* const  n = nodes.at(i);
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


void  progress_recorder::typed_minimization_progress_info::save_info(std::ostream&  ostr) const
{
    TMPROF_BLOCK();

    ostr << "\"from_variables_to_input\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)from_variables_to_input.size(); i < end; ++i)
    {
        typed_minimization_analysis::mapping_to_input_bits const&  mapping = from_variables_to_input.at(i);
        ostr << mapping.input_start_bit_index << ", " << mapping.value_bit_indices.size() << ",  ";
        for (natural_32_bit  j = 0U, j_end = (natural_32_bit)mapping.value_bit_indices.size(); j < j_end; ++j)
        {
            ostr << (natural_32_bit)mapping.value_bit_indices.at(j);
            if (j + 1 < j_end) ostr << ',';
        }
        if (i + 1 < end) ostr << ",\n";
    }
    ostr << "],\n\"types_of_variables\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)types_of_variables.size(); i < end; ++i)
    {
        ostr << '\"' << to_string(types_of_variables.at(i)) << '\"';
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"all_input_bits\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bits_and_types->bits.size(); i < end; ++i)
    {
        if (i % 8U == 0U) ostr << '\n';
        ostr << (bits_and_types->bits.at(i) ? '1' : '0');
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"all_input_types\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bits_and_types->types.size(); i < end; ++i)
    {
        if (i % 8U == 0U) ostr << '\n';
        ostr << '\"' << to_string(bits_and_types->types.at(i)) << '\"';
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"execution_cache_hits\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)execution_cache_hits.size(); i < end; ++i)
    {
        ostr << execution_cache_hits.at(i).trace_index << ','
             << execution_cache_hits.at(i).variables_hash << ",\"";
        switch (execution_cache_hits.at(i).progress_stage)
        {
            case typed_minimization_analysis::SEED: ostr << "SEED"; break;
            case typed_minimization_analysis::PARTIALS: ostr << "PARTIALS"; break;
            case typed_minimization_analysis::STEP: ostr << "STEP"; break;
        }
        ostr << '\"';
        if (i + 1 < end) ostr << ',';
        ostr << '\n';
    }
    ostr << "]";
}


void  progress_recorder::minimization_progress_info::save_info(std::ostream&  ostr) const
{
    TMPROF_BLOCK();

    ostr << "\"bit_translation\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bit_translation.size(); i < end; ++i)
    {
        ostr << bit_translation.at(i);
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"all_input_bits\": [";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)bits_and_types->bits.size(); i < end; ++i)
    {
        if (i % 8U == 0U) ostr << '\n';
        ostr << (bits_and_types->bits.at(i) ? '1' : '0');
        if (i + 1 < end) ostr << ',';
    }
    ostr << "],\n\"stage_changes\": [\n";
    for (natural_32_bit  i = 0U, end = (natural_32_bit)stage_changes.size(); i < end; ++i)
    {
        ostr << stage_changes.at(i).index << ",\"";
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


void  progress_recorder::on_strategy_turn_primary_loop_head()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::PRIMARY_LOOP_HEAD);
}


void  progress_recorder::on_strategy_turn_primary_sensitive()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::PRIMARY_SENSITIVE);
}


void  progress_recorder::on_strategy_turn_primary_untouched()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::PRIMARY_UNTOUCHED);
}


void  progress_recorder::on_strategy_turn_primary_iid_twins()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::PRIMARY_IID_TWINS);
}


void  progress_recorder::on_strategy_turn_monte_carlo()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::MONTE_CARLO);
}


void  progress_recorder::on_strategy_turn_monte_carlo_backward()
{
    if (!is_started())
        return;
    post_data.on_strategy_changed(post_analysis_data::MONTE_CARLO_BACKWARD);
}


void  progress_recorder::on_post_node_closed(branching_node* const  node)
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
    , strategy{ NONE }
    , closed_node_guids{}
{}


void  progress_recorder::post_analysis_data::on_strategy_changed(STRATEGY const  strategy_)
{
   strategy = strategy_; 
}


void  progress_recorder::post_analysis_data::on_node_closed(branching_node* const  node)
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
    strategy = NONE;
    closed_node_guids.clear();
}


bool  progress_recorder::post_analysis_data::empty() const
{
    return strategy == NONE && closed_node_guids.empty();
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
        case NONE: ostr << "NONE"; break;
        case PRIMARY_LOOP_HEAD: ostr << "PRIMARY_LOOP_HEAD"; break;
        case PRIMARY_SENSITIVE: ostr << "PRIMARY_SENSITIVE"; break;
        case PRIMARY_UNTOUCHED: ostr << "PRIMARY_UNTOUCHED"; break;
        case PRIMARY_IID_TWINS: ostr << "PRIMARY_IID_TWINS"; break;
        case MONTE_CARLO: ostr << "MONTE_CARLO"; break;
        case MONTE_CARLO_BACKWARD: ostr << "MONTE_CARLO_BACKWARD"; break;
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
