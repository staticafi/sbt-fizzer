#ifndef STD_PAIR_HASH_HPP_INCLUDED
#   define STD_PAIR_HASH_HPP_INCLUDED

#   include <functional>
#   include <utility/hash_combine.hpp>


namespace std
{


template<typename S, typename T>
struct hash< pair<S,T> >
{
    inline size_t operator()(const pair<S,T> & v) const
    {
        size_t seed = 0;
        ::hash_combine(seed, v.first);
        ::hash_combine(seed, v.second);
        return seed;
    }
};


}


#endif
