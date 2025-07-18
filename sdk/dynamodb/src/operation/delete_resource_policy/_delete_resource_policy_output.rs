// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteResourcePolicyOutput {
    /// <p>A unique string that represents the revision ID of the policy. If you're comparing revision IDs, make sure to always use string comparison logic.</p>
    /// <p>This value will be empty if you make a request against a resource without a policy.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourcePolicyOutput {
    /// <p>A unique string that represents the revision ID of the policy. If you're comparing revision IDs, make sure to always use string comparison logic.</p>
    /// <p>This value will be empty if you make a request against a resource without a policy.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteResourcePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteResourcePolicyOutput {
    /// Creates a new builder-style object to manufacture [`DeleteResourcePolicyOutput`](crate::operation::delete_resource_policy::DeleteResourcePolicyOutput).
    pub fn builder() -> crate::operation::delete_resource_policy::builders::DeleteResourcePolicyOutputBuilder {
        crate::operation::delete_resource_policy::builders::DeleteResourcePolicyOutputBuilder::default()
    }
}

/// A builder for [`DeleteResourcePolicyOutput`](crate::operation::delete_resource_policy::DeleteResourcePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteResourcePolicyOutputBuilder {
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourcePolicyOutputBuilder {
    /// <p>A unique string that represents the revision ID of the policy. If you're comparing revision IDs, make sure to always use string comparison logic.</p>
    /// <p>This value will be empty if you make a request against a resource without a policy.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that represents the revision ID of the policy. If you're comparing revision IDs, make sure to always use string comparison logic.</p>
    /// <p>This value will be empty if you make a request against a resource without a policy.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>A unique string that represents the revision ID of the policy. If you're comparing revision IDs, make sure to always use string comparison logic.</p>
    /// <p>This value will be empty if you make a request against a resource without a policy.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteResourcePolicyOutput`](crate::operation::delete_resource_policy::DeleteResourcePolicyOutput).
    pub fn build(self) -> crate::operation::delete_resource_policy::DeleteResourcePolicyOutput {
        crate::operation::delete_resource_policy::DeleteResourcePolicyOutput {
            revision_id: self.revision_id,
            _request_id: self._request_id,
        }
    }
}
