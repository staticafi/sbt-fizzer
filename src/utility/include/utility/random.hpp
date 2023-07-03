#ifndef UTILITY_RANDOM_HPP_INCLUDED
#   define UTILITY_RANDOM_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <random>
#   include <functional>
#   include <vector>


//The classic Minimum Standard rand0 of Lewis, Goodman, and Miller.
using  random_generator_for_natural_32_bit = std::linear_congruential_engine<natural_32_bit, 16807UL, 0UL, 2147483647UL>;
using  random_generator_for_natural_64_bit = std::linear_congruential_engine<natural_64_bit, 16807UL, 0UL, 2147483647UL>;

// An alternative LCR (Lehmer Generator function).
//typedef std::linear_congruential_engine<natural_32_bit, 48271UL, 0UL, 2147483647UL> random_generator_for_natural_32_bit;

// The classic Mersenne Twister.
//typedef std::mersenne_twister_engine<natural_32_bit, 32, 624, 397, 31,
//                                                     0x9908b0dfUL, 11,
//                                                     0xffffffffUL, 7,
//                                                     0x9d2c5680UL, 15,
//                                                     0xefc60000UL, 18, 1812433253UL> random_generator_for_natural_32_bit;


random_generator_for_natural_32_bit&  default_random_generator();

natural_32_bit  get_random_natural_32_bit_in_range(
    natural_32_bit const min_value,
    natural_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator = default_random_generator()
    );

integer_32_bit  get_random_integer_32_bit_in_range(
    integer_32_bit const min_value,
    integer_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator = default_random_generator()
    );

float_32_bit  get_random_float_32_bit_in_range(
    float_32_bit const min_value,
    float_32_bit const max_value,
    random_generator_for_natural_32_bit&   generator
    );
float_32_bit  get_random_float_32_bit(random_generator_for_natural_32_bit&  generator);

void  reset(random_generator_for_natural_32_bit&  generator,
            natural_32_bit const  seed = random_generator_for_natural_32_bit::default_seed);


natural_64_bit  get_random_natural_64_bit_in_range(
    natural_64_bit const  min_value,
    natural_64_bit const  max_value,
    random_generator_for_natural_64_bit&  generator
    );

integer_64_bit  get_random_integer_64_bit_in_range(
    integer_64_bit const  min_value,
    integer_64_bit const  max_value,
    random_generator_for_natural_64_bit&  generator
    );

float_64_bit  get_random_float_64_bit_in_range(
    float_64_bit const min_value,
    float_64_bit const max_value,
    random_generator_for_natural_64_bit&   generator
    );
float_64_bit  get_random_float_64_bit(random_generator_for_natural_64_bit&  generator);

void  reset(random_generator_for_natural_64_bit&  generator,
            natural_64_bit const  seed = random_generator_for_natural_64_bit::default_seed);


using  bar_random_distribution = std::vector<float_32_bit>;

inline natural_32_bit  get_num_bars(bar_random_distribution const&  bar_distribution)
{ return static_cast<natural_32_bit>(bar_distribution.size()); }

bar_random_distribution  make_bar_random_distribution_from_count_bars(
        std::vector<natural_64_bit> const&  count_bars
        );
bar_random_distribution  make_bar_random_distribution_from_size_bars(
        std::vector<float_32_bit> const&  size_bars
        );
bar_random_distribution  make_bar_random_distribution_from_probability_bars(
        std::vector<float_32_bit> const&  probability_bars
        );

natural_32_bit  get_random_bar_index(
    bar_random_distribution const&  bar_distribution,
    random_generator_for_natural_32_bit&   generator
    );


/// It is completely specified by a function which does whole the computation.
/// It can be any non-decreasing function mapping interval [0,1] to interval [0,1].
/// Typically, the function represents the inverted sum (integral) of some desired
/// probability distribution and then scaled into range [0,1].
using  function_random_distribution = std::function<float_32_bit(float_32_bit)>;

float_32_bit  get_random_float_32_bit_in_range(
        float_32_bit const min_value,
        float_32_bit const max_value,
        function_random_distribution const&  distribution,
        random_generator_for_natural_32_bit&   generator
        );

inline function_random_distribution  get_uniform_distribution_function()
{
    return [](float_32_bit const  x) -> float_32_bit { return x; };
}

inline function_random_distribution  get_hermit_sigma_distribution_function()
{
    return [](float_32_bit const  x) -> float_32_bit { float_32_bit const  x2 = x*x; return 3.0f*x2 - 2.0f*x2*x; };
}

inline function_random_distribution  get_decreasing_distribution_function(float_32_bit const  a)
{
    return std::bind([](float_32_bit const  x, float_32_bit const  a) -> float_32_bit { return std::pow(x,a); },
                     std::placeholders::_1,
                     a);
}

inline function_random_distribution  get_increasing_distribution_function(float_32_bit const  a)
{
    return std::bind([](float_32_bit const  x, float_32_bit const  a) -> float_32_bit { return 1.0f - std::pow(1.0f-x,a); },
                     std::placeholders::_1,
                     a);
}


#endif
