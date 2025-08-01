// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGroupMembershipOutput {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    _request_id: Option<String>,
}
impl DeleteGroupMembershipOutput {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
}
impl ::aws_types::request_id::RequestId for DeleteGroupMembershipOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteGroupMembershipOutput {
    /// Creates a new builder-style object to manufacture [`DeleteGroupMembershipOutput`](crate::operation::delete_group_membership::DeleteGroupMembershipOutput).
    pub fn builder() -> crate::operation::delete_group_membership::builders::DeleteGroupMembershipOutputBuilder {
        crate::operation::delete_group_membership::builders::DeleteGroupMembershipOutputBuilder::default()
    }
}

/// A builder for [`DeleteGroupMembershipOutput`](crate::operation::delete_group_membership::DeleteGroupMembershipOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGroupMembershipOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl DeleteGroupMembershipOutputBuilder {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteGroupMembershipOutput`](crate::operation::delete_group_membership::DeleteGroupMembershipOutput).
    pub fn build(self) -> crate::operation::delete_group_membership::DeleteGroupMembershipOutput {
        crate::operation::delete_group_membership::DeleteGroupMembershipOutput {
            request_id: self.request_id,
            status: self.status.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
