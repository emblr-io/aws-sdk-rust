// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourcePermissionOutput {
    /// <p></p>
    pub policy: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourcePermissionOutput {
    /// <p></p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourcePermissionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourcePermissionOutput {
    /// Creates a new builder-style object to manufacture [`GetResourcePermissionOutput`](crate::operation::get_resource_permission::GetResourcePermissionOutput).
    pub fn builder() -> crate::operation::get_resource_permission::builders::GetResourcePermissionOutputBuilder {
        crate::operation::get_resource_permission::builders::GetResourcePermissionOutputBuilder::default()
    }
}

/// A builder for [`GetResourcePermissionOutput`](crate::operation::get_resource_permission::GetResourcePermissionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourcePermissionOutputBuilder {
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourcePermissionOutputBuilder {
    /// <p></p>
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p></p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetResourcePermissionOutput`](crate::operation::get_resource_permission::GetResourcePermissionOutput).
    pub fn build(self) -> crate::operation::get_resource_permission::GetResourcePermissionOutput {
        crate::operation::get_resource_permission::GetResourcePermissionOutput {
            policy: self.policy,
            _request_id: self._request_id,
        }
    }
}
