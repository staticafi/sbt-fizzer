#include <utility/math.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <unordered_set>
#include <algorithm>


natural_16_bit  hamming_distance(vecb const&  bits1, vecb const&  bits2)
{
    natural_16_bit  dist = 0U;
    std::size_t const  n = std::min(bits1.size(), bits2.size());
    for (std::size_t i = 0UL; i != n; ++i)
        dist += bits1.at(i) == bits2.at(i) ? 0U : 1U;
    return dist + (natural_16_bit)(std::max(bits1.size(), bits2.size()) - n);
}


bool  copy_bits_to_bytes_array(natural_8_bit* output_bytes_array, std::size_t const num_array_bytes, bool as_signed, vecb const&  bits, bool const little_endian)
{
    if (bits.empty())
        return true;

    std::size_t const  num_bytes = (bits.size() + 7UL) / 8UL;

    if (num_array_bytes < num_bytes)
        return false;

    std::size_t const  num_bits = 8UL * num_bytes;

    vecb  bits_(num_bits, false);
    std::copy(bits.begin(), bits.end(), bits_.begin());

    for (natural_8_bit* ptr = output_bytes_array, *end = ptr + num_array_bytes; ptr != end; ++ptr)
        *ptr = as_signed && bits_.at(bits_.size() - 8UL) ? 0xFFU : 0x00U;

    natural_8_bit* const begin = output_bytes_array + (little_endian ? 0UL : num_array_bytes - num_bytes);
    natural_8_bit* ptr = begin;

    int count_to_8 = 0;
    for (bool bit : bits_)
    {
        auto const value = (natural_8_bit)(1 << (7 - count_to_8));
        if (bit)
            *ptr |= value;
        else
            *ptr &= (natural_8_bit)0xFFU - value;

        if (++count_to_8 == 8)
        {
            ++ptr;
            count_to_8 = 0;
        }
    }

    if (!little_endian)
        std::reverse(begin, ptr);

    return true;
}


std::size_t  make_hash(vecb::const_iterator  begin, vecb::const_iterator const end, std::size_t seed)
{
    for (std::size_t  i = 13UL; begin != end; ++begin, i += 97UL)
        hash_combine(seed, i * (std::size_t)(*begin ? 71UL : 11UL));
    return seed;
}


bool  inc(vecb&  bits, bool const  little_endian)
{
    if (little_endian)
        for (std::size_t i = 0UL; i < bits.size(); i += 8UL)
        {
            for (std::size_t j = 0UL, n = std::min((std::size_t)8UL, bits.size() - i); j != n; ++j)
            {
                auto  b = at(bits, i + (n - 1UL - j));
                b = !b;
                if (b)
                    return true;
            }
        }
    else
        for (auto it = bits.rbegin(); it != bits.rend(); ++it)
        {
            *it = !*it;
            if (*it)
                return true;
        }
    return false;
}


mat<natural_64_bit> const&  pascal_triangle()
{
    static mat<natural_64_bit> const  pt = []() {
        std::size_t const NUM_ROWS = 64UL;
        mat<natural_64_bit> m;
        for (std::size_t i = 0UL; i != NUM_ROWS; ++i)
            m.push_back(vecu64(i + 1UL, 1UL));
        for (std::size_t i = 2UL; i != NUM_ROWS; ++i)
            for (std::size_t j = 1UL; j != i; ++j)
                at(m, i, j) = at(m, i - 1UL, j - 1UL) + at(m, i - 1UL, j);
        return m;
    }();
    return pt;
}


vecu64 const&  pascal_triangle_row(natural_8_bit  n)
{
    return pascal_triangle().at(std::min(n,(natural_8_bit)(pascal_triangle().size() - 1UL)));
}


natural_64_bit  n_choose_k(natural_8_bit  n, natural_8_bit  k)
{
    return at(pascal_triangle_row(n), std::min(k,(natural_8_bit)(pascal_triangle().size() - 1UL)));
}


std::size_t  sample_counts_per_hamming_class(vecu64&  output_counts, std::size_t const  num_bits, std::size_t const  total_samples_count)
{
    vecu64 const&  row = pascal_triangle_row((natural_8_bit)std::min(num_bits, (std::size_t)std::numeric_limits<natural_8_bit>::max()));
    natural_64_bit const s = sum(row);
    float_64_bit const c = (float_64_bit)std::min(s, (natural_64_bit)total_samples_count);
    std::size_t  total_count = 0ULL;
    for (auto x : row)
    {
        natural_64_bit const  count = (natural_64_bit)std::max(1.0, c * ((float_64_bit)x / (float_64_bit)s) + 0.5);
        output_counts.push_back(count);
        total_count += count;
    }
    return total_count;
}


void  generate_sample_of_hamming_class(vecb&  output_bits, std::size_t const  num_bits, std::size_t const  hamming_class,
                                       random_generator_for_natural_32_bit&  generator)
{
    if (hamming_class > num_bits / 2UL)
    {
        generate_sample_of_hamming_class(output_bits, num_bits, num_bits - hamming_class, generator);
        for (std::size_t  i = 0UL; i != output_bits.size(); ++i)
            output_bits.at(i) = !output_bits.at(i);
        return;
    }
    output_bits.clear();
    output_bits.resize(num_bits, false);
    for (std::size_t  i = 0UL; i != hamming_class; ++i)
    {
        std::size_t  idx;
        do
            idx = get_random_natural_32_bit_in_range(0U, (natural_32_bit)(num_bits - 1UL), generator);
        while (output_bits.at(idx));
        output_bits.at(idx) = true;
    }
}


void  generate_samples_of_hamming_class(vec<vecb>&  output_samples, std::size_t const  num_bits, std::size_t const  hamming_class,
                                        std::size_t const  num_samples_to_generate, random_generator_for_natural_32_bit&  generator)
{
    std::unordered_set<std::size_t>  hashes;
    for (std::size_t  i = 0UL; i != num_samples_to_generate; ++i)
    {
        output_samples.push_back({});
        for (std::size_t j = 0; true; ++j)
        {
            INVARIANT(j < 1000 * num_samples_to_generate); // We should never be that unlucky. Otherwise we should change the algorithm.
            generate_sample_of_hamming_class(output_samples.back(), num_bits, hamming_class, generator);
            std::size_t const  h = make_hash(output_samples.back());
            if (hashes.count(h) == 0UL)
            {
                hashes.insert(h);
                break;
            }
            output_samples.back().clear();
        }
    }
}


void  bits_to_bytes(vecb const&  bits, vecu8&  bytes)
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)bits.size(); i < n; )
    {
        bytes.push_back(0U);
        for (natural_32_bit  j = i; i < n && i - j < 8U; ++i)
            if (bits.at(i))
                bytes.back() |= (1 << (7U - (i - j)));
    }
}


void  bytes_to_bits(vecu8 const&  bytes, vecb&  bits)
{
    for (natural_8_bit const  byte : bytes)
        for (natural_8_bit  i = 0U; i != 8U; ++i)
            bits.push_back(byte & (1 << (7U - i)));
}


void  bytes_to_bits(natural_8_bit const*  begin, natural_8_bit const* const  end, vecb&  bits)
{
    for ( ; begin != end; ++begin)
        for (natural_8_bit  i = 0U; i != 8U; ++i)
            bits.push_back((*begin) & (1 << (7U - i)));
}
