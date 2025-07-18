// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub(crate) fn reflens_describe_load_balancers_output_output_next_marker(
    input: &crate::operation::describe_load_balancers::DescribeLoadBalancersOutput,
) -> ::std::option::Option<&::std::string::String> {
    let input = match &input.next_marker {
        ::std::option::Option::None => return ::std::option::Option::None,
        ::std::option::Option::Some(t) => t,
    };
    ::std::option::Option::Some(input)
}

pub(crate) fn lens_describe_load_balancers_output_output_load_balancer_descriptions(
    input: crate::operation::describe_load_balancers::DescribeLoadBalancersOutput,
) -> ::std::option::Option<::std::vec::Vec<crate::types::LoadBalancerDescription>> {
    let input = input.load_balancer_descriptions?;
    ::std::option::Option::Some(input)
}
