// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOriginRequestPolicyInput {
    /// <p>The unique identifier for the origin request policy. If the origin request policy is attached to a distribution's cache behavior, you can get the policy's identifier using <code>ListDistributions</code> or <code>GetDistribution</code>. If the origin request policy is not attached to a cache behavior, you can get the identifier using <code>ListOriginRequestPolicies</code>.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetOriginRequestPolicyInput {
    /// <p>The unique identifier for the origin request policy. If the origin request policy is attached to a distribution's cache behavior, you can get the policy's identifier using <code>ListDistributions</code> or <code>GetDistribution</code>. If the origin request policy is not attached to a cache behavior, you can get the identifier using <code>ListOriginRequestPolicies</code>.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetOriginRequestPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetOriginRequestPolicyInput`](crate::operation::get_origin_request_policy::GetOriginRequestPolicyInput).
    pub fn builder() -> crate::operation::get_origin_request_policy::builders::GetOriginRequestPolicyInputBuilder {
        crate::operation::get_origin_request_policy::builders::GetOriginRequestPolicyInputBuilder::default()
    }
}

/// A builder for [`GetOriginRequestPolicyInput`](crate::operation::get_origin_request_policy::GetOriginRequestPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOriginRequestPolicyInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetOriginRequestPolicyInputBuilder {
    /// <p>The unique identifier for the origin request policy. If the origin request policy is attached to a distribution's cache behavior, you can get the policy's identifier using <code>ListDistributions</code> or <code>GetDistribution</code>. If the origin request policy is not attached to a cache behavior, you can get the identifier using <code>ListOriginRequestPolicies</code>.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the origin request policy. If the origin request policy is attached to a distribution's cache behavior, you can get the policy's identifier using <code>ListDistributions</code> or <code>GetDistribution</code>. If the origin request policy is not attached to a cache behavior, you can get the identifier using <code>ListOriginRequestPolicies</code>.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the origin request policy. If the origin request policy is attached to a distribution's cache behavior, you can get the policy's identifier using <code>ListDistributions</code> or <code>GetDistribution</code>. If the origin request policy is not attached to a cache behavior, you can get the identifier using <code>ListOriginRequestPolicies</code>.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetOriginRequestPolicyInput`](crate::operation::get_origin_request_policy::GetOriginRequestPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_origin_request_policy::GetOriginRequestPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_origin_request_policy::GetOriginRequestPolicyInput { id: self.id })
    }
}
