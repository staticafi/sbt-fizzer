#ifndef UTILITY_MATH_HPP_INCLUDED
#   define UTILITY_MATH_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <utility/assumptions.hpp>
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
std::size_t rows(mat<T> const& m)
{
    return m.size();
}

template<typename T>
std::size_t columns(mat<T> const& m)
{
    return m.empty() ? 0UL : m.front().size();
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

template<typename T, typename S>
vec<T>& add(vec<T>& v, S const a)
{
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(v,i) += (T)a;
    return v;
}

template<typename T, typename S>
vec<T> add_cp(vec<T> const& v, S const a)
{
    vec<T> result = v;
    for (std::size_t  i = 0UL; i != v.size(); ++i)
        at(result,i) += (T)a;
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


void  bits_to_bytes(vecb const&  bits, vecu8&  bytes);
void  bytes_to_bits(vecu8 const&  bytes, vecb&  bits);
void  bytes_to_bits(natural_8_bit const*  begin, natural_8_bit const* end, vecb&  bits);


#endif
