#ifndef INSTRUMENTATION_INSTRUMENTATION_HPP_INCLUDED
#   define INSTRUMENTATION_INSTRUMENTATION_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <iomodels/instrumentation_callbacks.hpp>
#   include <utility/invariants.hpp>
#   include <functional>
#   include <string>
#   include <cmath>
#   include <type_traits>
#   include <boost/type_traits/promote.hpp>

#   define IF_(V1, CMP, V2)                                 \
        if (instrumentation::___on_branching___(            \
            (instrumentation::location_id)__LINE__,         \
            (V1),                                           \
            (V2),                                           \
            instrumentation::OPCODE::CMP))

#   define WHILE_(V1, CMP, V2)                              \
        while (instrumentation::___on_branching___(         \
            (instrumentation::location_id)__LINE__,         \
            (V1),                                           \
            (V2),                                           \
            instrumentation::OPCODE::CMP))

#   define FOR_(INIT, V1, CMP, V2, INC)                     \
        for (INIT; instrumentation::___on_branching___(     \
            (instrumentation::location_id)__LINE__,         \
            (V1),                                           \
            (V2),                                           \
            instrumentation::OPCODE::CMP); INC)

#   define READ_STDIN_(VAR)                                 \
        do {                                                \
            static_assert(sizeof(VAR) <= 32, "Can only read variables of size up to 32 bits."); \
            static_assert(!std::is_array<decltype(VAR)>::value, "Cannot read array type."); \
            iomodels::on_read_stdin(                        \
                (instrumentation::location_id)__LINE__,     \
                (natural_8_bit*)(&VAR),                     \
                (natural_8_bit)sizeof(VAR));                \
        } while (false)

#   define WRITE_STDOUT_(VAR)                               \
        do {                                                \
            static_assert(sizeof(VAR) <= 32, "Can only write variables of size up to 32 bits."); \
            static_assert(!std::is_array<decltype(VAR)>::value, "Cannot write array type."); \
            auto const _______________tmp = VAR;            \
            iomodels::on_write_stdout(                      \
                (instrumentation::location_id)__LINE__,     \
                (natural_8_bit const*)&_______________tmp,  \
                (natural_8_bit)sizeof(_______________tmp)); \
        } while (false)

#   define DRIVER_TYPE_  std::function<void()>
#   define DRIVER_NAME_  DRIVER
#   define DRIVER_()  void DRIVER_NAME_()

namespace  instrumentation {


enum struct  OPCODE
{
    EQ  = 1,
    NE  = 2,
    LT  = 3,
    LE  = 4,
    GT  = 5,
    GE  = 6,
};


template<typename T1, typename T2>
struct comparison_common_type
{
    typedef typename boost::promote<typename std::decay<T1>::type>::type promotion_type_1;
    typedef typename boost::promote<typename std::decay<T2>::type>::type promotion_type_2;
    typedef typename std::common_type<promotion_type_1,promotion_type_2>::type type;
};


template<typename T1, typename T2>
bool  ___on_branching___(location_id const  id, T1 const  value_1, T2 const  value_2, OPCODE const  opcode)
{
    branching_coverage_info  info(id);
    {
        typedef typename comparison_common_type<T1,T2>::type T;
        T const  v_1 = (T)value_1;
        T const  v_2 = (T)value_2;
        coverage_distance_type const  v1 = (coverage_distance_type)v_1; // Must init from v_1, NOT from value_1!!
        coverage_distance_type const  v2 = (coverage_distance_type)v_2; // Must init from v_2, NOT from value_2!!
        coverage_distance_type const  one = (coverage_distance_type)1;
        switch (opcode)
        {
            case OPCODE::EQ:
                info.covered_branch = v_1 == v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? one : (v1 < v2 ? v2 - v1 : v1 - v2);
                break;
            case OPCODE::NE:
                info.covered_branch = v_1 != v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? (v1 < v2 ? v2 - v1 : v1 - v2) : one;
                break;
            case OPCODE::LT:
                info.covered_branch = v_1 < v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? v2 - v1 : v1 - v2 + one;
                break;
            case OPCODE::LE:
                info.covered_branch = v_1 <= v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? v2 - v1 + one : v1 - v2;
                break;
            case OPCODE::GT:
                info.covered_branch = v_1 > v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? v1 - v2 : v2 - v1 + one;
                break;
            case OPCODE::GE:
                info.covered_branch = v_1 >= v_2;
                info.distance_to_uncovered_branch = info.covered_branch ? v1 - v2 + one : v2 - v1;
                break;
            default:
                UNREACHABLE();
        }
    }
    if (std::isnan(info.distance_to_uncovered_branch))
        info.distance_to_uncovered_branch = std::numeric_limits<coverage_distance_type>::max();
    INVARIANT(info.distance_to_uncovered_branch > (coverage_distance_type)0);
    iomodels::on_branching(info);
    return info.covered_branch;
}


}

#endif
