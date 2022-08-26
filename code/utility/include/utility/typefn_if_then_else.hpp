#ifndef TYPEFN_IF_THEN_ELSE_HPP_INCLUDED
#   define TYPEFN_IF_THEN_ELSE_HPP_INCLUDED


template<bool condition, typename return_type_when_condition_is_true
                       , typename return_type_when_condition_is_false>
struct typefn_if_then_else
{
    typedef return_type_when_condition_is_true result;
private:
    result by_this_attribute_we_check_that_we_can_create_instance_of_resulting_type;
};

template<typename return_type_when_condition_is_true, typename return_type_when_condition_is_false>
struct typefn_if_then_else<false,return_type_when_condition_is_true,return_type_when_condition_is_false>
{
    typedef return_type_when_condition_is_false result;
private:
    result by_this_attribute_we_check_that_we_can_create_instance_of_resulting_type;
};


#endif
