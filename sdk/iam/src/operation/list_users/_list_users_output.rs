// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html">ListUsers</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListUsersOutput {
    /// <p>A list of users.</p>
    pub users: ::std::vec::Vec<crate::types::User>,
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: bool,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListUsersOutput {
    /// <p>A list of users.</p>
    pub fn users(&self) -> &[crate::types::User] {
        use std::ops::Deref;
        self.users.deref()
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListUsersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListUsersOutput {
    /// Creates a new builder-style object to manufacture [`ListUsersOutput`](crate::operation::list_users::ListUsersOutput).
    pub fn builder() -> crate::operation::list_users::builders::ListUsersOutputBuilder {
        crate::operation::list_users::builders::ListUsersOutputBuilder::default()
    }
}

/// A builder for [`ListUsersOutput`](crate::operation::list_users::ListUsersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListUsersOutputBuilder {
    pub(crate) users: ::std::option::Option<::std::vec::Vec<crate::types::User>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListUsersOutputBuilder {
    /// Appends an item to `users`.
    ///
    /// To override the contents of this collection use [`set_users`](Self::set_users).
    ///
    /// <p>A list of users.</p>
    pub fn users(mut self, input: crate::types::User) -> Self {
        let mut v = self.users.unwrap_or_default();
        v.push(input);
        self.users = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of users.</p>
    pub fn set_users(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::User>>) -> Self {
        self.users = input;
        self
    }
    /// <p>A list of users.</p>
    pub fn get_users(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::User>> {
        &self.users
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListUsersOutput`](crate::operation::list_users::ListUsersOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`users`](crate::operation::list_users::builders::ListUsersOutputBuilder::users)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_users::ListUsersOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_users::ListUsersOutput {
            users: self.users.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "users",
                    "users was not specified but it is required when building ListUsersOutput",
                )
            })?,
            is_truncated: self.is_truncated.unwrap_or_default(),
            marker: self.marker,
            _request_id: self._request_id,
        })
    }
}
