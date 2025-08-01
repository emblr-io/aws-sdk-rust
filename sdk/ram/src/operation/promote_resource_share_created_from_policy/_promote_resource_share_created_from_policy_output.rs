// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PromoteResourceShareCreatedFromPolicyOutput {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub return_value: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl PromoteResourceShareCreatedFromPolicyOutput {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn return_value(&self) -> ::std::option::Option<bool> {
        self.return_value
    }
}
impl ::aws_types::request_id::RequestId for PromoteResourceShareCreatedFromPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PromoteResourceShareCreatedFromPolicyOutput {
    /// Creates a new builder-style object to manufacture [`PromoteResourceShareCreatedFromPolicyOutput`](crate::operation::promote_resource_share_created_from_policy::PromoteResourceShareCreatedFromPolicyOutput).
    pub fn builder() -> crate::operation::promote_resource_share_created_from_policy::builders::PromoteResourceShareCreatedFromPolicyOutputBuilder {
        crate::operation::promote_resource_share_created_from_policy::builders::PromoteResourceShareCreatedFromPolicyOutputBuilder::default()
    }
}

/// A builder for [`PromoteResourceShareCreatedFromPolicyOutput`](crate::operation::promote_resource_share_created_from_policy::PromoteResourceShareCreatedFromPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PromoteResourceShareCreatedFromPolicyOutputBuilder {
    pub(crate) return_value: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl PromoteResourceShareCreatedFromPolicyOutputBuilder {
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn return_value(mut self, input: bool) -> Self {
        self.return_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn set_return_value(mut self, input: ::std::option::Option<bool>) -> Self {
        self.return_value = input;
        self
    }
    /// <p>A return value of <code>true</code> indicates that the request succeeded. A value of <code>false</code> indicates that the request failed.</p>
    pub fn get_return_value(&self) -> &::std::option::Option<bool> {
        &self.return_value
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PromoteResourceShareCreatedFromPolicyOutput`](crate::operation::promote_resource_share_created_from_policy::PromoteResourceShareCreatedFromPolicyOutput).
    pub fn build(self) -> crate::operation::promote_resource_share_created_from_policy::PromoteResourceShareCreatedFromPolicyOutput {
        crate::operation::promote_resource_share_created_from_policy::PromoteResourceShareCreatedFromPolicyOutput {
            return_value: self.return_value,
            _request_id: self._request_id,
        }
    }
}
