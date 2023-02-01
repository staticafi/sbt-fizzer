#ifndef FUZZHAMM_IID_FUZZER_BASE_HPP_INCLUDED
#   define FUZZHAMM_IID_FUZZER_BASE_HPP_INCLUDED

#   include <fuzzhamm/execution_trace.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <unordered_set>
#   include <memory>

namespace  fuzzhamm {


using namespace instrumentation;


struct  iid_fuzzer_base
{
    explicit  iid_fuzzer_base(location_id  id);
    virtual  ~iid_fuzzer_base() = default;

    void  on_new_trace(execution_trace_ptr const  trace, std::unordered_set<natural_32_bit> const&  target_branching_indices);
    void  on_sample(execution_trace_ptr  sample_trace);
    void  compute_input(vecb&  input_stdin);

    [[nodiscard]] location_id  loc_id() const { return loc_id_; }
    [[nodiscard]] random_generator_for_natural_32_bit&   get_generator() { return generator; }
    [[nodiscard]] natural_32_bit  get_num_inputs_generated() const { return num_inputs_generated; }

    virtual bool  done() const = 0;
    virtual float_64_bit  processing_penalty() const = 0;

protected:

    virtual void  new_trace(execution_trace_ptr const  trace, std::unordered_set<natural_32_bit> const&  target_branching_indices) {}
    virtual void  update(execution_trace_ptr  sample_trace) {}
    virtual void  generate(vecb&  input_stdin) = 0;

private:
    location_id  loc_id_;
    random_generator_for_natural_32_bit   generator;
    natural_32_bit  num_inputs_generated;
};


using  iid_fuzzer_base_ptr = std::shared_ptr<iid_fuzzer_base>;


}

#endif
