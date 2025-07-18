// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLifecyclePolicyOutput {
    /// <p>The identifier of the lifecycle policy.</p>
    pub policy_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateLifecyclePolicyOutput {
    /// <p>The identifier of the lifecycle policy.</p>
    pub fn policy_id(&self) -> ::std::option::Option<&str> {
        self.policy_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateLifecyclePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateLifecyclePolicyOutput {
    /// Creates a new builder-style object to manufacture [`CreateLifecyclePolicyOutput`](crate::operation::create_lifecycle_policy::CreateLifecyclePolicyOutput).
    pub fn builder() -> crate::operation::create_lifecycle_policy::builders::CreateLifecyclePolicyOutputBuilder {
        crate::operation::create_lifecycle_policy::builders::CreateLifecyclePolicyOutputBuilder::default()
    }
}

/// A builder for [`CreateLifecyclePolicyOutput`](crate::operation::create_lifecycle_policy::CreateLifecyclePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateLifecyclePolicyOutputBuilder {
    pub(crate) policy_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateLifecyclePolicyOutputBuilder {
    /// <p>The identifier of the lifecycle policy.</p>
    pub fn policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the lifecycle policy.</p>
    pub fn set_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_id = input;
        self
    }
    /// <p>The identifier of the lifecycle policy.</p>
    pub fn get_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateLifecyclePolicyOutput`](crate::operation::create_lifecycle_policy::CreateLifecyclePolicyOutput).
    pub fn build(self) -> crate::operation::create_lifecycle_policy::CreateLifecyclePolicyOutput {
        crate::operation::create_lifecycle_policy::CreateLifecyclePolicyOutput {
            policy_id: self.policy_id,
            _request_id: self._request_id,
        }
    }
}
