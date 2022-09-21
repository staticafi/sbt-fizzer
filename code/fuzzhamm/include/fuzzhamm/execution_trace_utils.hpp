#ifndef FUZZHAMM_EXECUTION_TRACE_UTILS_HPP_INCLUDED
#   define FUZZHAMM_EXECUTION_TRACE_UTILS_HPP_INCLUDED

#   include <fuzzhamm/execution_trace.hpp>
#   include <fuzzhamm/sensitivity_fuzzer_sequence.hpp>
#   include <fuzzhamm/branching_fuzzer_sequence.hpp>
#   include <fuzzhamm/iid_fuzzer_base.hpp>
#   include <utility/assumptions.hpp>
#   include <vector>
#   include <unordered_set>
#   include <unordered_map>
#   include <iosfwd>

namespace  fuzzhamm {


void  to_json(std::ostream&  ostr, execution_trace const&  trace, bool  dump_trace, bool  dump_dbg_info);


sensitivity_fuzzer_base_ptr  create_sensitivity_fuzzer(execution_trace_weak_ptr  the_trace, bool  similarity_only_for_uncovered_branchings);
branching_fuzzer_sequence_ptr  create_branching_fuzzer_sequence(
        execution_trace_record const&  rec,
        vecb const&  input_stdin,
        random_generator_for_natural_32_bit&  random_generator
        );
iid_fuzzer_base_ptr  create_iid_fuzzer(location_id const  loc_id);


void  compute_escape_sensitive_bits_for_branchings(execution_trace_const_ptr  trace, std::vector<std::unordered_set<natural_16_bit> >&  result);
void  split_branching_sensitive_bits_to_pure_and_escape(
            std::unordered_set<natural_16_bit> const&  branching_all_sensitive_bits,
            std::unordered_set<natural_16_bit> const&  branching_escape_sensitive_bits,
            std::unordered_set<natural_16_bit>&  pure_sensitive_bits,
            std::unordered_set<natural_16_bit>*  escape_sensitive_bits = nullptr
            );


using  branchings_indices_map = std::unordered_map<location_id, std::vector<natural_32_bit> >;
void  compute_indices_of_branchings(std::vector<execution_trace_record> const&  branching_records, branchings_indices_map&  result);
void  compute_indices_of_location_id(std::vector<execution_trace_record> const&  branching_records, location_id  id, std::vector<natural_32_bit>&  result);
natural_32_bit  index_of_branching_record_with_min_coverage_distance(std::vector<execution_trace_record> const&  branching_records, location_id  id);
std::size_t  compute_diverging_branch_index(
        std::vector<execution_trace_record> const&  reference_branching_records,
        std::vector<execution_trace_record> const&  checked_branching_records,
        std::size_t  end_index
        );
inline std::size_t  compute_diverging_branch_index(
        std::vector<execution_trace_record> const&  reference_branching_records,
        std::vector<execution_trace_record> const&  checked_branching_records
        )
{ return compute_diverging_branch_index(reference_branching_records, checked_branching_records, reference_branching_records.size()); }


template<typename iterator_type>
natural_32_bit  index_of_branching_record_with_min_coverage_distance(
        std::vector<execution_trace_record> const&  branching_records,
        iterator_type  indices_begin,
        iterator_type const  indices_end)
{
    ASSUMPTION(indices_begin != indices_end);
    natural_32_bit  best_index = *indices_begin;
    for ( ; indices_begin != indices_end; ++indices_begin)
        if (branching_records.at(*indices_begin).coverage_info.distance_to_uncovered_branch
                < branching_records.at(best_index).coverage_info.distance_to_uncovered_branch)
            best_index = *indices_begin;
    return  best_index;
}


struct  branchings_hitcounts
{
    natural_32_bit  num_hits_true_branch    = 0U;
    natural_32_bit  num_hits_false_branch   = 0U;
};
using  branchings_hitcounts_map = std::unordered_map<location_id, branchings_hitcounts>;
void  compute_hitcounts_of_branchings(std::vector<execution_trace_record> const&  branching_records, branchings_hitcounts_map&  result);


void  compute_histograms_of_branchings(
        std::vector<execution_trace_record> const&  branching_records,
        location_id  loc_id,
        std::vector<std::pair<natural_32_bit, std::unordered_map<location_id, std::pair<natural_32_bit, natural_32_bit> > > >&  histograms
        );


struct  branching_classification
{
    std::unordered_map<location_id, bool>  border;
    std::unordered_set<location_id>  inner;
    std::unordered_set<location_id>  loop_body;
    std::unordered_set<location_id>  loop_head;

    void  merge(branching_classification const&  other);
};
void  classify_branchings(std::vector<execution_trace_record> const&  branching_records, branching_classification&  result);


struct  branching_and_direction
{
    struct hasher
    {
        inline size_t operator()(branching_and_direction const&  value) const
        {
            size_t seed = 0;
            ::hash_combine(seed, value.branching_id);
            ::hash_combine(seed, value.covered_branch);
            return seed;
        }
    };

    bool  operator==(branching_and_direction const&  other) const
    { return branching_id == other.branching_id && covered_branch == other.covered_branch; }

    branching_and_direction()
        : branching_id(invalid_location_id())
        , covered_branch(false)
    {}

    branching_and_direction(location_id const  branching_id_, bool const  covered_branch_)
        : branching_id(branching_id_)
        , covered_branch(covered_branch_)
    {}

    location_id  branching_id;
    bool  covered_branch;
};


void  compute_diverged_and_colliding_stdin_bits(std::vector<execution_trace_record>&  branching_records);


struct  did_branching_selection_penalty
{
    did_branching_selection_penalty();
    did_branching_selection_penalty(execution_trace_record const&  rec);

    natural_32_bit  num_sensitive_bits;
    natural_32_bit  num_diverged_bits;
    natural_32_bit  num_colliding_bits;
};

bool  operator<(did_branching_selection_penalty const&  left, did_branching_selection_penalty const&  right);


struct  iid_branching_direction_switching_stats
{
    iid_branching_direction_switching_stats()
        : num_target_miss_samples(0U)
        , num_target_hit_samples(0U)
        , sum_of_produced_coverage_changes(0.0)
    {}

    natural_32_bit  num_target_miss_samples;
    natural_32_bit  num_target_hit_samples;
    coverage_distance_type  sum_of_produced_coverage_changes;
};

using  iid_branching_direction_switching_stats_map =
        std::unordered_map<branching_and_direction, iid_branching_direction_switching_stats, branching_and_direction::hasher>;

bool  operator<(iid_branching_direction_switching_stats const&  left, iid_branching_direction_switching_stats const&  right);


struct  iid_branching_selection_penalty
{
    iid_branching_selection_penalty();
    iid_branching_selection_penalty(
            branching_and_direction const&  branching,
            branching_classification const&  classification,
            iid_branching_direction_switching_stats_map&  switching_stats
            );

    bool  is_border;
    bool  is_loop_body;
    bool  is_loop_head;
    iid_branching_direction_switching_stats const*  stats_ptr;
};

bool  operator<(iid_branching_selection_penalty const&  left, iid_branching_selection_penalty const&  right);


}

#endif
