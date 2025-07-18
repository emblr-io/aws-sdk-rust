// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserOutput {
    /// <p>The user object that has been deleted.</p>
    pub user: ::std::option::Option<crate::types::User>,
    _request_id: Option<String>,
}
impl DeleteUserOutput {
    /// <p>The user object that has been deleted.</p>
    pub fn user(&self) -> ::std::option::Option<&crate::types::User> {
        self.user.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteUserOutput {
    /// Creates a new builder-style object to manufacture [`DeleteUserOutput`](crate::operation::delete_user::DeleteUserOutput).
    pub fn builder() -> crate::operation::delete_user::builders::DeleteUserOutputBuilder {
        crate::operation::delete_user::builders::DeleteUserOutputBuilder::default()
    }
}

/// A builder for [`DeleteUserOutput`](crate::operation::delete_user::DeleteUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserOutputBuilder {
    pub(crate) user: ::std::option::Option<crate::types::User>,
    _request_id: Option<String>,
}
impl DeleteUserOutputBuilder {
    /// <p>The user object that has been deleted.</p>
    pub fn user(mut self, input: crate::types::User) -> Self {
        self.user = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user object that has been deleted.</p>
    pub fn set_user(mut self, input: ::std::option::Option<crate::types::User>) -> Self {
        self.user = input;
        self
    }
    /// <p>The user object that has been deleted.</p>
    pub fn get_user(&self) -> &::std::option::Option<crate::types::User> {
        &self.user
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteUserOutput`](crate::operation::delete_user::DeleteUserOutput).
    pub fn build(self) -> crate::operation::delete_user::DeleteUserOutput {
        crate::operation::delete_user::DeleteUserOutput {
            user: self.user,
            _request_id: self._request_id,
        }
    }
}
