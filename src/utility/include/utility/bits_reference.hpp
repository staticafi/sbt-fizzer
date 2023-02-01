#ifndef UTILITY_BITS_REFERENCE_HPP_INCLUDED
#   define UTILITY_BITS_REFERENCE_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <utility/bit_count.hpp>
#   include <utility/assumptions.hpp>


struct bits_reference;
struct bits_const_reference;

namespace private_internal_implementation_details {

struct bits_reference_impl
{
    bits_reference_impl(
        natural_8_bit* const first_byte_ptr,
        natural_8_bit const shift_in_the_first_byte,
        natural_16_bit const num_bits
        );

    natural_8_bit* first_byte_ptr();
    natural_8_bit const* first_byte_ptr() const;
    natural_8_bit shift_in_the_first_byte() const;
    natural_16_bit num_bits() const;

private:
    natural_8_bit* m_first_byte_ptr;
    natural_16_bit m_num_bits;
    natural_8_bit m_shift_in_the_first_byte;
};

bool operator==(bits_reference_impl const& left, bits_reference_impl const& right);

bits_reference_impl& get_impl(bits_reference const& bits_ref);
bits_reference_impl& get_impl(bits_const_reference const& bits_ref);

}


struct bits_const_reference;


struct bits_reference
{
    bits_reference(
            natural_8_bit* const first_byte_ptr,
            natural_8_bit const shift_in_the_first_byte,
            natural_16_bit const num_bits
            )
        : m_data(first_byte_ptr,shift_in_the_first_byte,num_bits)
    {}

    operator  bits_const_reference() const;

    natural_8_bit*  first_byte_ptr() { return m_data.first_byte_ptr(); }
    natural_8_bit const*  first_byte_ptr() const { return m_data.first_byte_ptr(); }
    natural_8_bit  shift_in_the_first_byte() const { return m_data.shift_in_the_first_byte(); }
    natural_16_bit  num_bits() const { return m_data.num_bits(); }

private:
    friend private_internal_implementation_details::bits_reference_impl&
    private_internal_implementation_details::get_impl(bits_reference const& bits_ref);

    private_internal_implementation_details::bits_reference_impl  m_data;
};

struct bits_const_reference
{
    bits_const_reference(
            natural_8_bit const* const first_byte_ptr,
            natural_8_bit const shift_in_the_first_byte,
            natural_16_bit const num_bits
            )
        : m_data(const_cast<natural_8_bit*>(first_byte_ptr),shift_in_the_first_byte,num_bits)
    {}

    bits_const_reference(bits_reference const& bits);
    bits_const_reference(bits_reference&& bits);
    bits_const_reference&  operator=(bits_reference const& bits);
    bits_const_reference&  operator=(bits_reference&& bits);

    natural_8_bit const*  first_byte_ptr() const { return m_data.first_byte_ptr(); }
    natural_8_bit  shift_in_the_first_byte() const { return m_data.shift_in_the_first_byte(); }
    natural_16_bit  num_bits() const { return m_data.num_bits(); }

private:
    friend private_internal_implementation_details::bits_reference_impl&
    private_internal_implementation_details::get_impl(bits_const_reference const& bits_ref);

    private_internal_implementation_details::bits_reference_impl  m_data;
};

bool operator==(bits_reference const& left, bits_reference const& right);
bool operator==(bits_reference const& left, bits_const_reference const& right);
bool operator==(bits_const_reference const& left, bits_reference const& right);
bool operator==(bits_const_reference const& left, bits_const_reference const& right);

bool  get_bit(bits_reference const& bits_ref, natural_16_bit const bit_index);
bool  get_bit(bits_const_reference const& bits_ref, natural_16_bit const bit_index);
void  set_bit(bits_reference& bits_ref, natural_16_bit const bit_index, bool const value);
void  swap_referenced_bits( bits_reference& left_bits, bits_reference& right_bits);

void  bits_to_value(
    bits_reference const& source_bits,
    natural_8_bit index_of_the_first_bit,
    natural_8_bit how_many_bits,
    natural_32_bit& variable_where_the_value_will_be_stored
    );

void  bits_to_value(
    bits_const_reference const& source_bits,
    natural_8_bit index_of_the_first_bit,
    natural_8_bit how_many_bits,
    natural_32_bit& variable_where_the_value_will_be_stored
    );

template<typename T, typename bits_reference_type>
T  bits_to_value(
    bits_reference_type const& bits_ref,
    natural_8_bit index_of_the_first_bit,
    natural_16_bit how_many_bits
    )
{
    ASSUMPTION(how_many_bits <= sizeof(T) * 8U);
    T variable_where_the_value_will_be_stored;
    bits_to_value(
            bits_ref,
            index_of_the_first_bit,
            (typename smallest_natural_type_storing_bit_count_of<T>::result)how_many_bits,
            variable_where_the_value_will_be_stored
            );
    return variable_where_the_value_will_be_stored;
}

template<typename T, typename bits_reference_type>
T  bits_to_value( bits_reference_type const& bits_ref )
{
    return bits_to_value<T>( bits_ref, 0U, bits_ref.num_bits() );
}

void value_to_bits(
    natural_32_bit const variable_where_the_value_is_stored,
    bits_reference const& target_bits,
    natural_8_bit const index_of_the_first_target_bit,
    natural_8_bit const how_many_bits_to_transfer
    );

void value_to_bits(
    natural_32_bit const variable_where_the_value_is_stored,
    bits_reference const& target_bits
    );


#endif
