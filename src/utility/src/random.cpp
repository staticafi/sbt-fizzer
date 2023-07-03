#include <utility/random.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <limits>
#include <algorithm>
#include <iterator>


random_generator_for_natural_32_bit&  default_random_generator()
{
    static random_generator_for_natural_32_bit the_generator;
    return the_generator;
}


natural_32_bit  get_random_natural_32_bit_in_range(
    natural_32_bit const min_value,
    natural_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator
    )
{
    ASSUMPTION(min_value <= max_value);
    return std::uniform_int_distribution<natural_32_bit>(min_value,max_value)(generator);
}

integer_32_bit  get_random_integer_32_bit_in_range(
    integer_32_bit const min_value,
    integer_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator
    )
{
    ASSUMPTION(min_value <= max_value);
    return std::uniform_int_distribution<integer_32_bit>(min_value,max_value)(generator);
}

float_32_bit  get_random_float_32_bit_in_range(
    float_32_bit const min_value,
    float_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator
    )
{
    ASSUMPTION(min_value <= max_value);
    if (std::isfinite(max_value - min_value))
    {
        float_64_bit const  coef =
                static_cast<float_64_bit>(get_random_natural_32_bit_in_range(0U,std::numeric_limits<natural_32_bit>::max(),generator))
                / static_cast<float_64_bit>(std::numeric_limits<natural_32_bit>::max());
        return static_cast<float_32_bit>((1.0 - coef) * min_value + coef * max_value);
    }
    return get_random_float_32_bit(generator);
}


float_32_bit  get_random_float_32_bit(random_generator_for_natural_32_bit&  generator)
{
    float_32_bit  result;
    *((natural_32_bit*)&result) = get_random_natural_32_bit_in_range(0U,std::numeric_limits<natural_32_bit>::max(),generator);
    return result;
}

void  reset(random_generator_for_natural_32_bit&  generator, natural_32_bit const  seed)
{
    generator.seed(seed);
}


natural_64_bit  get_random_natural_64_bit_in_range(
    natural_64_bit const  min_value,
    natural_64_bit const  max_value,
    random_generator_for_natural_64_bit&  generator
    )
{
    ASSUMPTION(min_value <= max_value);
    return std::uniform_int_distribution<natural_64_bit>(min_value,max_value)(generator);
}

integer_64_bit  get_random_integer_64_bit_in_range(
    integer_64_bit const  min_value,
    integer_64_bit const  max_value,
    random_generator_for_natural_64_bit&  generator
    )
{
    ASSUMPTION(min_value <= max_value);
    return std::uniform_int_distribution<integer_64_bit>(min_value,max_value)(generator);
}

float_64_bit  get_random_float_64_bit_in_range(
    float_64_bit const min_value,
    float_64_bit const max_value,
    random_generator_for_natural_64_bit&   generator
    )
{
    ASSUMPTION(min_value <= max_value);
    if (std::isfinite(max_value - min_value))
    {
        float_64_bit const  coef =
                static_cast<float_64_bit>(get_random_natural_64_bit_in_range(0ULL,std::numeric_limits<natural_64_bit>::max(),generator))
                / static_cast<float_64_bit>(std::numeric_limits<natural_64_bit>::max());
        return (1.0 - coef) * min_value + coef * max_value;
    }
    return get_random_float_64_bit(generator);
}


float_64_bit  get_random_float_64_bit(random_generator_for_natural_64_bit&  generator)
{
    float_64_bit  result;
    *((natural_64_bit*)&result) = get_random_natural_64_bit_in_range(0ULL,std::numeric_limits<natural_64_bit>::max(),generator);
    return result;
}

void  reset(random_generator_for_natural_64_bit&  generator, natural_64_bit const  seed)
{
    generator.seed(seed);
}


bar_random_distribution  make_bar_random_distribution_from_count_bars(
        std::vector<natural_64_bit> const&  count_bars
        )
{
    ASSUMPTION(count_bars.size() <= std::numeric_limits<natural_32_bit>::max());
    natural_64_bit  sum_of_counts = 0UL;
    for (auto const&  count : count_bars)
        sum_of_counts += count;
    if (sum_of_counts == 0UL)
        return {1.0f};
    std::vector<float_32_bit> probability_bars;
    for (auto const&  count : count_bars)
        probability_bars.push_back(
            static_cast<float_32_bit>(static_cast<float_64_bit>(count) / static_cast<float_64_bit>(sum_of_counts))
            );
    return make_bar_random_distribution_from_probability_bars(probability_bars);
}

bar_random_distribution  make_bar_random_distribution_from_size_bars(
        std::vector<float_32_bit> const&  size_bars
        )
{
    ASSUMPTION(size_bars.size() <= std::numeric_limits<natural_32_bit>::max());
    float_64_bit  sum_of_sizes = 0.0;
    for (auto const  size : size_bars)
    {
        ASSUMPTION(size >= 0.0);
        sum_of_sizes += size;
    }
    if (sum_of_sizes < 1e-5)
        return {1.0f};
    std::vector<float_32_bit> probability_bars;
    for (auto const&  size : size_bars)
        probability_bars.push_back(static_cast<float_32_bit>(static_cast<float_64_bit>(size) / sum_of_sizes));
    return make_bar_random_distribution_from_probability_bars(probability_bars);
}

bar_random_distribution  make_bar_random_distribution_from_probability_bars(
        std::vector<float_32_bit> const&  probability_bars
        )
{
    ASSUMPTION(probability_bars.size() <= std::numeric_limits<natural_32_bit>::max());
    ASSUMPTION(!probability_bars.empty());
    float_32_bit  sum_of_probabilities = 0.0f;
    bar_random_distribution  distribution;
    for (auto const&  probability : probability_bars)
    {
        ASSUMPTION(probability >= 0.0f);
        sum_of_probabilities += probability;
        ASSUMPTION(sum_of_probabilities < 1.001f);
        distribution.push_back(sum_of_probabilities);
    }
    INVARIANT(!distribution.empty());
    INVARIANT(probability_bars.size() == distribution.size());
    ASSUMPTION(distribution.back() > 0.999f && distribution.back() < 1.001f);
    distribution.back() = 1.0f;
    return distribution;
}

natural_32_bit  get_random_bar_index(
    bar_random_distribution const&  bar_distribution,
    random_generator_for_natural_32_bit&   generator
    )
{
    bar_random_distribution::const_iterator const  it =
            std::upper_bound(
                    bar_distribution.cbegin(),
                    bar_distribution.cend(),
                    get_random_float_32_bit_in_range(0.0f,1.0f,generator)
                    );
    return static_cast<natural_32_bit>(
                (it == bar_distribution.cend()) ? bar_distribution.size() - 1UL :
                                                  std::distance(bar_distribution.cbegin(),it)
                );
}

float_32_bit  get_random_float_32_bit_in_range(
        float_32_bit const min_value,
        float_32_bit const max_value,
        function_random_distribution const&  distribution,
        random_generator_for_natural_32_bit&   generator
        )
{
    float_32_bit const  param = distribution(get_random_float_32_bit_in_range(0.0f,1.0f,generator));
    return std::min(std::max(min_value,min_value + param * (max_value - min_value)),max_value);
}



//#include <utility/invariants.hpp>
//#include <vector>
//#include <limits>
//#include <cmath>
//#include <algorithm>




//struct probability_mass_function
//{
//    probability_mass_function(
//            std::vector<natural_32_bit> const& values_of_random_variable, // must be sorted!
//            std::vector<natural_32_bit> const& frequences_of_values_of_random_variable
//            )
//        : m_values_of_random_variable(values_of_random_variable)
//        , m_cumulative_distribution_function(frequences_of_values_of_random_variable.size(),0U)
//    {
//        ASSUMPTION(values_of_random_variable.size() > 0);
//        ASSUMPTION(values_of_random_variable.size() == frequences_of_values_of_random_variable.size());
//        ASSUMPTION(m_cumulative_distribution_function.size() == frequences_of_values_of_random_variable.size());
//        // TODO: Check for sortedness of values_of_random_variable!


//        // TODO: the following code is wrong: It does not add values appearing in between two adjacent
//        //       values in the array frequences_of_values_of_random_variable. Linear interpolation
//        //       should be used to compute summary value of all such inner values.


//        natural_64_bit  raw_sum = 0ULL;
//        for (auto frequency : frequences_of_values_of_random_variable)
//            raw_sum += frequency;
//        ASSUMPTION(raw_sum > 0ULL);

//        natural_32_bit const  max_value = std::numeric_limits<natural_32_bit>::max();

//        float_64_bit const  scale = static_cast<float_64_bit>(max_value) / static_cast<float_64_bit>(raw_sum);

//        m_cumulative_distribution_function.at(0) =
//                static_cast<natural_32_bit>(
//                    std::round( scale * frequences_of_values_of_random_variable.at(0) )
//                    );
//        for (natural_32_bit i = 1U; i < m_cumulative_distribution_function.size() - 1U; ++i)
//            m_cumulative_distribution_function.at(i) = m_cumulative_distribution_function.at(i-1) +
//                    static_cast<natural_32_bit>(
//                        std::round( scale * frequences_of_values_of_random_variable.at(i) )
//                        );
//        m_cumulative_distribution_function.at(m_cumulative_distribution_function.size() - 1U) = max_value;
//    }

//    std::vector<natural_32_bit> const&  values_of_random_variable() const { return m_values_of_random_variable; }
//    std::vector<natural_32_bit> const&  cumulative_distribution_function() const { return m_cumulative_distribution_function; }
//    //natural_32_bit  operator ()() const;

//private:
//    std::vector<natural_32_bit> m_values_of_random_variable;
//    std::vector<natural_32_bit> m_cumulative_distribution_function;
//};


//natural_32_bit  get_random_natural_32_bit(probability_mass_function const& mass_function)
//{
//    natural_32_bit const key = get_random_natural_32_bit_in_range(0U,std::numeric_limits<natural_32_bit>::max());

//    std::vector<natural_32_bit>::const_iterator const it =
//            std::lower_bound(
//                    mass_function.cumulative_distribution_function().begin(),
//                    mass_function.cumulative_distribution_function().end(),
//                    key
//                    );
//    INVARIANT(it != mass_function.cumulative_distribution_function().end());
//    if (it == mass_function.cumulative_distribution_function().begin())
//        return mass_function.values_of_random_variable().at(0);

//    natural_32_bit const x1 = std::distance(it,mass_function.cumulative_distribution_function().begin());
//    natural_32_bit const x0 = x1 - 1U;

//    natural_32_bit const y1 = mass_function.cumulative_distribution_function().at(x1);
//    natural_32_bit const y0 = mass_function.cumulative_distribution_function().at(x0);

//    (void)y1;
//    (void)y0;

//    // TODO: not done yet! An index in between [x0,x1] should be computed and returned. Use values
//    //       key, y0, and y1 for the computation. Here key represents a "scale" between y0 and y1.
//    //       But it is NOT a linear interpolation!

//    return x1; // This is not correct (it solves compile error)
//}



////void foo()
////{
////    probability_mass_function  pmf({1,2},{3,4});
////    natural_32_bit  rndval =  get_random_natural_32_bit(pmf);

////}

