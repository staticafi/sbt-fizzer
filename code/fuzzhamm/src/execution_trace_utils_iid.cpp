#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


bool  operator<(iid_branching_direction_switching_stats const&  left, iid_branching_direction_switching_stats const&  right)
{
    coverage_distance_type constexpr  miss_coverage_change = 1000.0;

    coverage_distance_type const  left_hit_improve_rate = left.sum_of_produced_coverage_changes / (left.num_target_hit_samples + 1U);
    coverage_distance_type const  left_improve_rate = left_hit_improve_rate + miss_coverage_change * left.num_target_miss_samples;
    coverage_distance_type const  left_coef = left_improve_rate < 0.0 ? 1.0 - left_improve_rate : 1.0 / (1.0 + left_improve_rate);
    coverage_distance_type const  left_potential = left_coef * right.num_target_hit_samples;

    coverage_distance_type const  right_hit_improve_rate = right.sum_of_produced_coverage_changes / (right.num_target_hit_samples + 1U);
    coverage_distance_type const  right_improve_rate = right_hit_improve_rate + miss_coverage_change * right.num_target_miss_samples;
    coverage_distance_type const  right_coef = right_improve_rate < 0.0 ? 1.0 - right_improve_rate : 1.0 / (1.0 + right_improve_rate);
    coverage_distance_type const  right_potential = right_coef * left.num_target_hit_samples;

    return left_potential > right_potential;
}


iid_branching_selection_penalty::iid_branching_selection_penalty()
    : is_border(false)
    , is_loop_body(false)
    , is_loop_head(false)
    , stats_ptr(nullptr)
{}


iid_branching_selection_penalty::iid_branching_selection_penalty(
        branching_and_direction const&  branching,
        branching_classification const&  classification,
        iid_branching_direction_switching_stats_map&  switching_stats
        )
    : is_border(classification.border.count(branching.branching_id) != 0ULL)
    , is_loop_body(classification.loop_body.count(branching.branching_id) != 0ULL)
    , is_loop_head(classification.loop_head.count(branching.branching_id) != 0ULL)
    , stats_ptr(&switching_stats[branching])
{
    INVARIANT(!is_loop_head || !is_border);
}


bool  operator<(iid_branching_selection_penalty const&  left, iid_branching_selection_penalty const&  right)
{
    struct local
    {
        static inline bool cmp_stats_ptr(iid_branching_direction_switching_stats const* const  left, iid_branching_direction_switching_stats const* const  right)
        {
            return left == nullptr ? true : (right == nullptr ? false : (*left < *right));
        }
    };

    if (left.is_loop_body != right.is_loop_body)
        return left.is_loop_body;

    if (!left.is_loop_body)
    {
        if (left.is_border != right.is_border)
            return !left.is_border;
        return local::cmp_stats_ptr(left.stats_ptr, right.stats_ptr);
    }

    if (left.is_loop_head != right.is_loop_head)
        return !left.is_loop_head;

    if (left.is_loop_head)
        return local::cmp_stats_ptr(left.stats_ptr, right.stats_ptr);

    if (left.is_border != right.is_border)
        return !left.is_border;

    return local::cmp_stats_ptr(left.stats_ptr, right.stats_ptr);
}


}
