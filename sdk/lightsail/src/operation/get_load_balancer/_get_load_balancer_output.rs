// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLoadBalancerOutput {
    /// <p>An object containing information about your load balancer.</p>
    pub load_balancer: ::std::option::Option<crate::types::LoadBalancer>,
    _request_id: Option<String>,
}
impl GetLoadBalancerOutput {
    /// <p>An object containing information about your load balancer.</p>
    pub fn load_balancer(&self) -> ::std::option::Option<&crate::types::LoadBalancer> {
        self.load_balancer.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetLoadBalancerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLoadBalancerOutput {
    /// Creates a new builder-style object to manufacture [`GetLoadBalancerOutput`](crate::operation::get_load_balancer::GetLoadBalancerOutput).
    pub fn builder() -> crate::operation::get_load_balancer::builders::GetLoadBalancerOutputBuilder {
        crate::operation::get_load_balancer::builders::GetLoadBalancerOutputBuilder::default()
    }
}

/// A builder for [`GetLoadBalancerOutput`](crate::operation::get_load_balancer::GetLoadBalancerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLoadBalancerOutputBuilder {
    pub(crate) load_balancer: ::std::option::Option<crate::types::LoadBalancer>,
    _request_id: Option<String>,
}
impl GetLoadBalancerOutputBuilder {
    /// <p>An object containing information about your load balancer.</p>
    pub fn load_balancer(mut self, input: crate::types::LoadBalancer) -> Self {
        self.load_balancer = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object containing information about your load balancer.</p>
    pub fn set_load_balancer(mut self, input: ::std::option::Option<crate::types::LoadBalancer>) -> Self {
        self.load_balancer = input;
        self
    }
    /// <p>An object containing information about your load balancer.</p>
    pub fn get_load_balancer(&self) -> &::std::option::Option<crate::types::LoadBalancer> {
        &self.load_balancer
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLoadBalancerOutput`](crate::operation::get_load_balancer::GetLoadBalancerOutput).
    pub fn build(self) -> crate::operation::get_load_balancer::GetLoadBalancerOutput {
        crate::operation::get_load_balancer::GetLoadBalancerOutput {
            load_balancer: self.load_balancer,
            _request_id: self._request_id,
        }
    }
}
