// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutResourcePolicyOutput {
    /// <p>The policy that was created or updated.</p>
    pub resource_policy: ::std::option::Option<crate::types::ResourcePolicy>,
    _request_id: Option<String>,
}
impl PutResourcePolicyOutput {
    /// <p>The policy that was created or updated.</p>
    pub fn resource_policy(&self) -> ::std::option::Option<&crate::types::ResourcePolicy> {
        self.resource_policy.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutResourcePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutResourcePolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutResourcePolicyOutput`](crate::operation::put_resource_policy::PutResourcePolicyOutput).
    pub fn builder() -> crate::operation::put_resource_policy::builders::PutResourcePolicyOutputBuilder {
        crate::operation::put_resource_policy::builders::PutResourcePolicyOutputBuilder::default()
    }
}

/// A builder for [`PutResourcePolicyOutput`](crate::operation::put_resource_policy::PutResourcePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutResourcePolicyOutputBuilder {
    pub(crate) resource_policy: ::std::option::Option<crate::types::ResourcePolicy>,
    _request_id: Option<String>,
}
impl PutResourcePolicyOutputBuilder {
    /// <p>The policy that was created or updated.</p>
    pub fn resource_policy(mut self, input: crate::types::ResourcePolicy) -> Self {
        self.resource_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The policy that was created or updated.</p>
    pub fn set_resource_policy(mut self, input: ::std::option::Option<crate::types::ResourcePolicy>) -> Self {
        self.resource_policy = input;
        self
    }
    /// <p>The policy that was created or updated.</p>
    pub fn get_resource_policy(&self) -> &::std::option::Option<crate::types::ResourcePolicy> {
        &self.resource_policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutResourcePolicyOutput`](crate::operation::put_resource_policy::PutResourcePolicyOutput).
    pub fn build(self) -> crate::operation::put_resource_policy::PutResourcePolicyOutput {
        crate::operation::put_resource_policy::PutResourcePolicyOutput {
            resource_policy: self.resource_policy,
            _request_id: self._request_id,
        }
    }
}
