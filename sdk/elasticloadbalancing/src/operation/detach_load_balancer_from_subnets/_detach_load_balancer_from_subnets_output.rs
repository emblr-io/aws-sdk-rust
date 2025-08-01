// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of DetachLoadBalancerFromSubnets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetachLoadBalancerFromSubnetsOutput {
    /// <p>The IDs of the remaining subnets for the load balancer.</p>
    pub subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl DetachLoadBalancerFromSubnetsOutput {
    /// <p>The IDs of the remaining subnets for the load balancer.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnets.is_none()`.
    pub fn subnets(&self) -> &[::std::string::String] {
        self.subnets.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DetachLoadBalancerFromSubnetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DetachLoadBalancerFromSubnetsOutput {
    /// Creates a new builder-style object to manufacture [`DetachLoadBalancerFromSubnetsOutput`](crate::operation::detach_load_balancer_from_subnets::DetachLoadBalancerFromSubnetsOutput).
    pub fn builder() -> crate::operation::detach_load_balancer_from_subnets::builders::DetachLoadBalancerFromSubnetsOutputBuilder {
        crate::operation::detach_load_balancer_from_subnets::builders::DetachLoadBalancerFromSubnetsOutputBuilder::default()
    }
}

/// A builder for [`DetachLoadBalancerFromSubnetsOutput`](crate::operation::detach_load_balancer_from_subnets::DetachLoadBalancerFromSubnetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetachLoadBalancerFromSubnetsOutputBuilder {
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl DetachLoadBalancerFromSubnetsOutputBuilder {
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>The IDs of the remaining subnets for the load balancer.</p>
    pub fn subnets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input.into());
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the remaining subnets for the load balancer.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>The IDs of the remaining subnets for the load balancer.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnets
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DetachLoadBalancerFromSubnetsOutput`](crate::operation::detach_load_balancer_from_subnets::DetachLoadBalancerFromSubnetsOutput).
    pub fn build(self) -> crate::operation::detach_load_balancer_from_subnets::DetachLoadBalancerFromSubnetsOutput {
        crate::operation::detach_load_balancer_from_subnets::DetachLoadBalancerFromSubnetsOutput {
            subnets: self.subnets,
            _request_id: self._request_id,
        }
    }
}
