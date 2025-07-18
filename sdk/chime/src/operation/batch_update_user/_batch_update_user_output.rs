// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchUpdateUserOutput {
    /// <p>If the <code>BatchUpdateUser</code> action fails for one or more of the user IDs in the request, a list of the user IDs is returned, along with error codes and error messages.</p>
    pub user_errors: ::std::option::Option<::std::vec::Vec<crate::types::UserError>>,
    _request_id: Option<String>,
}
impl BatchUpdateUserOutput {
    /// <p>If the <code>BatchUpdateUser</code> action fails for one or more of the user IDs in the request, a list of the user IDs is returned, along with error codes and error messages.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_errors.is_none()`.
    pub fn user_errors(&self) -> &[crate::types::UserError] {
        self.user_errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchUpdateUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchUpdateUserOutput {
    /// Creates a new builder-style object to manufacture [`BatchUpdateUserOutput`](crate::operation::batch_update_user::BatchUpdateUserOutput).
    pub fn builder() -> crate::operation::batch_update_user::builders::BatchUpdateUserOutputBuilder {
        crate::operation::batch_update_user::builders::BatchUpdateUserOutputBuilder::default()
    }
}

/// A builder for [`BatchUpdateUserOutput`](crate::operation::batch_update_user::BatchUpdateUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchUpdateUserOutputBuilder {
    pub(crate) user_errors: ::std::option::Option<::std::vec::Vec<crate::types::UserError>>,
    _request_id: Option<String>,
}
impl BatchUpdateUserOutputBuilder {
    /// Appends an item to `user_errors`.
    ///
    /// To override the contents of this collection use [`set_user_errors`](Self::set_user_errors).
    ///
    /// <p>If the <code>BatchUpdateUser</code> action fails for one or more of the user IDs in the request, a list of the user IDs is returned, along with error codes and error messages.</p>
    pub fn user_errors(mut self, input: crate::types::UserError) -> Self {
        let mut v = self.user_errors.unwrap_or_default();
        v.push(input);
        self.user_errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>If the <code>BatchUpdateUser</code> action fails for one or more of the user IDs in the request, a list of the user IDs is returned, along with error codes and error messages.</p>
    pub fn set_user_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserError>>) -> Self {
        self.user_errors = input;
        self
    }
    /// <p>If the <code>BatchUpdateUser</code> action fails for one or more of the user IDs in the request, a list of the user IDs is returned, along with error codes and error messages.</p>
    pub fn get_user_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserError>> {
        &self.user_errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchUpdateUserOutput`](crate::operation::batch_update_user::BatchUpdateUserOutput).
    pub fn build(self) -> crate::operation::batch_update_user::BatchUpdateUserOutput {
        crate::operation::batch_update_user::BatchUpdateUserOutput {
            user_errors: self.user_errors,
            _request_id: self._request_id,
        }
    }
}
