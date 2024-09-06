#ifndef UTILITY_MATH_HPP_INCLUDED
#   define UTILITY_MATH_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <utility/assumptions.hpp>
#   include <utility/invariants.hpp>
#   include <utility/hash_combine.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <cmath>
#   include <type_traits>

template<typename T>
using vec = std::vector<T>;

template<typename T>
using mat = vec<vec<T> >;


using vecb = vec<bool>;
using veci8 = vec<integer_8_bit>;
using vecu8 = vec<natural_8_bit>;
using veci16 = vec<integer_16_bit>;
using vecu16 = vec<natural_16_bit>;
using veci32 = vec<integer_32_bit>;
using vecu32 = vec<natural_32_bit>;
using vecf32 = vec<float_32_bit>;
using veci64 = vec<integer_64_bit>;
using vecu64 = vec<natural_64_bit>;
using vecf64 = vec<float_64_bit>;

using matf64 = mat<float_64_bit>;


template<typename T, typename S>
vec<T> mkvec(std::size_t const n, S const& value = S{0})
{
    return vec<T>(n, (T)value);
}

template<typename T, typename S>
mat<T> mkmat(std::size_t const m, std::size_t const n, S const& value = S{0})
{
    return mat<T>(m, vec<T>(n, (T)value));
}

inline matf64 mkmatf64(std::size_t const m, std::size_t const n, float_64_bit const& value = 0.0)
{
    return mkmat<float_64_bit>(m, n, value);
}

template<typename S>
matf64 mkmatf64(std::size_t const m, std::size_t const n, S const& value = S{0})
{
    return mkmatf64(m, n, (float_64_bit)value);
}


template<typename T>
T at(vec<T> const& v, std::size_t const i)
{
    return v.at(i);
}

template<typename T>
typename vec<T>::reference  at(vec<T>& v, std::size_t const i)
{
    return v.at(i);
}


template<typename T>
T at(mat<T> const& m, std::size_t const i, std::size_t const j)
{
    return m.at(i).at(j);
}

template<typename T>
typename vec<T>::reference  at(mat<T>& m, std::size_t const i, std::size_t const j)
{
    return m.at(i).at(j);
}

template<typename T>
std::size_t size(vec<T> const& v)
{
    return v.size();
}

template<typename T>
std::size_t columns(mat<T> const& m)
{
    return m.size();
}

template<typename T>
std::size_t rows(mat<T> const& m)
{
    return m.empty() ? 0UL : m.front().size();
}

template<typename T>
vec<T> const&  column(mat<T> const& m, std::size_t const i)
{
    return m.at(i);
}

template<typename T>
vec<T>&  column(mat<T>& m, std::size_t const i)
{
    return m.at(i);
}


template<typename T, typename S>
vec<T>& set(vec<T>& v, S const& value = S{0})
{
    for (std::size_t  i = 0UL; i < size(v); ++i)
        at(v,i) = value;
    return v;
}


template<typename T, typename S>
vec<T>& reset(vec<T>& v, std::size_t const n, S const& value = S{0})
{
    v. resize(n);
    return set(v, value);
}


template<typename T>
vec<T>& axis(vec<T>& v, std::size_t const i)
{
    ASSUMPTION(i < size(v));
    set(v, (T)0);
    at(v, i) = (T)1;
    return v;
}


template<typename T>
vec<T>& axis(vec<T>& v, std::size_t const n, std::size_t const i)
{
    ASSUMPTION(i < n);
    reset(v, n, (T)0);
    at(v, i) = (T)1;
    return v;
}


template<typename T>
std::size_t arg_inf(vec<T> const& v)
{
    std::size_t  result = 0U;
    for (std::size_t  i = 1UL; i < v.size(); ++i)
        if (at(v,i) < at(v,result))
            result = i;
    return result;
}

template<typename T>
std::size_t arg_sup(vec<T> const& v)
{
    std::size_t  result = 0U;
    for (std::size_t  i = 1UL; i < v.size(); ++i)
        if (at(v,i) > at(v,result))
            result = i;
    return result;
}

template<typename T, typename S>
vec<T>& min_bound(vec<T>& v, S const bound)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) = std::max(at(v,i), (T)bound);
    return v;
}

template<typename T, typename S>
vec<T> min_bound_cp(vec<T> const& v, S const bound)
{
    vec<T> result = v;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(result,i) = std::max(at(result,i), (T)bound);
    return result;
}

template<typename T, typename S>
vec<T>& max_bound(vec<T>& v, S const bound)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) = std::min(at(v,i), (T)bound);
    return v;
}

template<typename T, typename S>
vec<T> max_bound_cp(vec<T> const& v, S const bound)
{
    vec<T> result = v;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(result,i) = std::min(at(result,i), (T)bound);
    return result;
}

template<typename T>
T sum(vec<T> const& v)
{
    T  result = (T)0;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        result += at(v,i);
    return result;
}

template<typename T>
T sum_abs(vec<T> const& v)
{
    T  result = (T)0;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        result += std::abs(at(v,i));
    return result;
}

template<typename T>
T max_abs(vec<T> const& v)
{
    if (v.empty())
        return (T)0;
    T  result = std::abs(v.front());
    for (std::size_t  i = 1UL; i != v.size(); ++i)
        result = std::max(std::abs(at(v,i)), result);
    return result;
}

template<typename T>
T min_abs(vec<T> const& v)
{
    if (v.empty())
        return (T)0;
    T  result = std::abs(v.front());
    for (std::size_t  i = 1UL; i != v.size(); ++i)
        result = std::min(std::abs(at(v,i)), result);
    return result;
}

template<typename T>
float_32_bit avg(vec<T> const& v)
{
    return v.empty() ? 0.0f : (float_32_bit)sum(v) / (float_32_bit)v.size();
}

template<typename T, typename S>
vec<T>& scale(vec<T>& v, S const a)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) *= (T)a;
    return v;
}

template<typename T, typename S>
vec<T> scale_cp(vec<T> const& v, S const a)
{
    vec<T> result = v;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(result,i) *= (T)a;
    return result;
}

template<typename T, typename S>
vec<T>& power(vec<T>& v, S const exponent)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) = std::pow(at(v,i), (T)exponent);
    return v;
}

template<typename T, typename S>
vec<T> power_cp(vec<T> const& v, S const exponent)
{
    vec<T> result = v;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(result,i) = std::pow(at(result,i), (T)exponent);
    return result;
}

template<typename T>
vec<T>& add(vec<T>& v, vec<T> const& u)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) += at(u,i);
    return v;
}

template<typename T>
vec<T> add_cp(vec<T> const& v, vec<T> const& u)
{
    vec<T> result{ v };
    return add(result, u);
}

template<typename T>
vec<T>& sub(vec<T>& v, vec<T> const& u)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) -= at(u,i);
    return v;
}

template<typename T>
vec<T> sub_cp(vec<T> const& v, vec<T> const& u)
{
    vec<T> result{ v };
    return sub(result, u);
}

template<typename T, typename S>
vec<T>& add_scaled(vec<T>& v, S const a, vec<T> const& u)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) += (T)a * at(u,i);
    return v;
}

template<typename T, typename S>
vec<T> add_scaled_cp(vec<T> const& v, S const a, vec<T> const& u)
{
    vec<T> result{ v };
    add_scaled(result, a, u);
    return result;
}

template<typename T>
vec<T>& negate(vec<T>& v)
{
    return scale(v, (T)-1);
}

template<typename T>
vec<T> negate_cp(vec<T> const& v)
{
    return scale_cp(v, (T)-1);
}

template<typename T>
vec<T> invert(vec<T> const& v)
{
    vec<T> w;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        w.push_back((T)1 / at(v,i));
    return w;
}

template<typename T>
vec<T> invert_cp(vec<T> const& v)
{
    vec<T> u{ v };
    invert(u);
    return u;
}

template<typename T>
vec<T> modulate(vec<T> const& v, vec<T> const& u)
{
    vec<T> w;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        w.push_back(at(v,i) * at(u,i));
    return w;
}

template<typename T>
T dot_product(vec<T> const& u, vec<T> const& v)
{
    T  result = (T)0;
    for (std::size_t  i = 0UL, n = std::min(u.size(), v.size()); i != n; ++i)
        result += u.at(i) * at(v,i);
    return result;
}

template<typename T>
T length(vec<T> const& v)
{
    return std::sqrt(dot_product(v,v));
}

template<typename T>
bool normalize(vec<T>& v)
{
    T const len = length(v);
    if (len < 0.001)
        return false;
    T const len_inv = (T)1 / len;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) *= len_inv;
    return true;
}

template<typename float_type>
bool isfinite(vec<float_type> const& v)
{
    static_assert(std::is_floating_point<float_type>::value, "");
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        if (!std::isfinite(at(v,i)) || std::isnan(at(v,i)))
            return false;
    return true;
}

template<typename T>
bool normalize_probabilities(vec<T>& v)
{
    T const s = sum(v);
    if (s < 0.001)
        return false;
    T const s_inv = (T)1 / s;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) *= s_inv;
    return true;
}

template<typename T>
vec<T> mul(mat<T> const& m, vec<T> const& v)
{
    vec<T> result;
    reset(result, rows(m), (T)0);
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        add_scaled(result, at(v, i), column(m, i));
    return result;
}

template<typename T>
vec<T>  component_of_first_orthogonal_to_second(vec<T> const&  u, vec<T> const&  v)
{
    vec<T> w{ u };
    add_scaled(w, -dot_product(u, v) / dot_product(v, v), v);
    return w;
}

template<typename float_type>
float_type  small_delta_around(float_type const x)
{
    static_assert(std::is_floating_point<float_type>::value, "Function works only for floating point types.");
    if (!std::isfinite(x) || std::isnan(x))
        return (float_type)0;
    int  x_exponent;
    std::frexp(x, &x_exponent);
    int const  delta_exponent{ x_exponent - (std::numeric_limits<decltype(x)>::digits >> 2) };
    float_64_bit const  delta{ std::pow(2.0, delta_exponent) };
    if (std::isfinite(x + delta) && !std::isnan(x + delta) && x + delta != x)
        return delta;
    else if (std::isfinite(x - delta) && !std::isnan(x - delta) && x - delta != x)
        return delta;
    return (float_type)0;
}


template<typename float_type>
struct  interval
{
    struct  bound
    {
        static inline bound inf_neg() { return { -std::numeric_limits<float_type>::infinity(), false }; }
        static inline bound inf_pos() { return {  std::numeric_limits<float_type>::infinity(), false }; }

        // bound() : value{ (float_type)0 }, inclusive{ true } {}

        bool  isfinite() const { return std::isfinite(value); }

        float_type value{ (float_type)0 };
        bool inclusive{ false };
    };

    // interval() : lo{ bound::inf_neg() }, hi{ bound::inf_pos() } {}

    bool  empty() const { return hi.value < lo.value || (hi.value == lo.value && (!hi.inclusive || !lo.inclusive)); }

    bound  lo{ bound::inf_neg() };
    bound  hi{ bound::inf_pos() };
};

template<typename float_type>
interval<float_type>  intersection(interval<float_type> const&  a, interval<float_type> const&  b)
{
    if (a.empty()) return a;
    if (b.empty()) return b;

    interval<float_type>  result{};

    if (a.lo.isfinite())
    {
        if (b.lo.isfinite())
        {
            if (a.lo.value == b.lo.value)
            {
                result.lo.value = a.lo.value;
                result.lo.inclusive = a.lo.inclusive && b.lo.inclusive;
            }
            else
                result.lo = a.lo.value < b.lo.value ? b.lo : a.lo;
        }
        else
            result.lo = a.lo;
    }
    else
        result.lo = b.lo;

    if (a.hi.isfinite())
    {
        if (b.hi.isfinite())
        {
            if (a.hi.value == b.hi.value)
            {
                result.hi.value = a.hi.value;
                result.hi.inclusive = a.hi.inclusive && b.hi.inclusive;
            }
            else
                result.hi = a.hi.value < b.hi.value ? a.hi : b.hi;
        }
        else
            result.hi = a.hi;
    }
    else
        result.hi = b.hi;

    return result;
}

template<typename float_type>
float_type  lowest(interval<float_type> const&  a)
{
    ASSUMPTION(!a.empty() && a.lo.isfinite());
    if (a.lo.inclusive)
        return a.lo.value;
    float_type const  result{ a.lo.value + std::fabs(small_delta_around(a.lo.value)) };
    if (a.hi.isfinite() && (result > a.hi.value || (result == a.hi.value && !a.hi.inclusive)))
        return (a.lo.value + a.hi.value) / (float_type)2;
    INVARIANT(std::isfinite(result));
    return result;
}

template<typename float_type>
float_type  highest(interval<float_type> const&  a)
{
    ASSUMPTION(!a.empty() && a.hi.isfinite());
    if (a.hi.inclusive)
        return a.hi.value;
    float_type const  result{ a.hi.value - std::fabs(small_delta_around(a.hi.value)) };
    if (a.lo.isfinite() && (result < a.lo.value || (result == a.lo.value && !a.lo.inclusive)))
        return (a.lo.value + a.hi.value) / (float_type)2;
    INVARIANT(std::isfinite(result));
    return result;
}

using intervalf32 = interval<float_32_bit>;
using intervalf64 = interval<float_64_bit>;


natural_16_bit  hamming_distance(vecb const&  bits1, vecb const&  bits2);
bool  copy_bits_to_bytes_array(natural_8_bit* output_bytes_array, std::size_t num_array_bytes, bool as_signed, vecb const&  bits, bool little_endian);


template<typename const_iterator>
std::size_t  make_hash(const_iterator  begin, const_iterator const end, std::size_t seed = 0UL)
{
    for (std::size_t  i = 13UL; begin != end; ++begin, i += 97UL)
        hash_combine(seed, (decltype(*begin))i * (*begin));
    return seed;
}


std::size_t  make_hash(vecb::const_iterator  begin, vecb::const_iterator const end, std::size_t seed = 0UL);


template<typename T>
std::size_t  make_hash(vec<T> const& v, std::size_t seed = 0UL)
{
    return make_hash(v.begin(), v.end(), seed);
}


inline std::size_t  make_hash(vecb const& v, std::size_t seed = 0UL)
{
    return make_hash(v.begin(), v.end(), seed);
}


template<typename T, typename S>
void  make_first_combination(std::vector<T>&  hamming_bit_indices, S const  num_indices)
{
    ASSUMPTION(num_indices > 0U);
    hamming_bit_indices.clear();
    for (auto i = (S)0; i != num_indices; ++i)
        hamming_bit_indices.push_back((T)i);
}


template<typename T, typename S>
bool  make_next_combination(std::vector<T>&  hamming_bit_indices, S const  num_input_bits)
{
    ASSUMPTION(!hamming_bit_indices.empty() && num_input_bits > 0U);
    for (auto i = (S)0, n = (S)hamming_bit_indices.size(); i != n; ++i)
    {
        S const  j = n - (i + (S)1);
        if (hamming_bit_indices.at(j) < (T)(num_input_bits - (i + (S)1)))
        {
            ++hamming_bit_indices.at(j);
            for (S k = j + (S)1; k < n; ++k)
                hamming_bit_indices.at(k) = hamming_bit_indices.at(j) + (T)(k - j);
            return true;
        }
    }
    return false;
}


template<typename T, typename S>
bool  is_last_combination(std::vector<T> const&  hamming_bit_indices, S const  num_input_bits)
{
    ASSUMPTION(!hamming_bit_indices.empty() && num_input_bits > 0U);
    for (auto i = (S)0, n = (S)hamming_bit_indices.size(); i != n; ++i)
        if (hamming_bit_indices.at(i) != num_input_bits - (n - i))
            return false;
    return true;
}


bool  inc(vecb&  bits, bool  little_endian);


mat<natural_64_bit> const&  pascal_triangle();
vecu64 const&  pascal_triangle_row(natural_8_bit  n);
natural_64_bit  n_choose_k(natural_8_bit  n, natural_8_bit  k);


std::size_t  sample_counts_per_hamming_class(vecu64&  output_counts, std::size_t  num_bits, std::size_t  total_samples_count);
void  generate_sample_of_hamming_class(vecb&  output_bits, std::size_t  num_bits, std::size_t  hamming_class,
                                       random_generator_for_natural_32_bit&  generator);
void  generate_samples_of_hamming_class(vec<vecb>&  output_samples, std::size_t const  num_bits, std::size_t const  hamming_class,
                                        std::size_t const  num_samples_to_generate, random_generator_for_natural_32_bit&  generator);


void  set_bit(natural_8_bit*  bytes, std::size_t  bit_index, bool  state);
bool  get_bit(natural_8_bit const*  bytes, std::size_t  bit_index);

void  bits_to_bytes(vecb const&  bits, vecu8&  bytes);
void  bytes_to_bits(vecu8 const&  bytes, vecb&  bits);
void  bytes_to_bits(natural_8_bit const*  begin, natural_8_bit const* end, vecb&  bits);


#endif
