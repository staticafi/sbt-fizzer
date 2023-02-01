#ifndef HASH_COMBINE_HPP_INCLUDED
#   define HASH_COMBINE_HPP_INCLUDED

#   include <functional>


template <typename S, typename T>
inline void hash_combine(S& seed, T const& value)
{
  std::hash<T> hasher;
  seed ^= hasher(value) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}


#endif
