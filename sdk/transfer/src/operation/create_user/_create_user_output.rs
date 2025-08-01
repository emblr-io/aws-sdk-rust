// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateUserOutput {
    /// <p>The identifier of the server that the user is attached to.</p>
    pub server_id: ::std::string::String,
    /// <p>A unique string that identifies a Transfer Family user.</p>
    pub user_name: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateUserOutput {
    /// <p>The identifier of the server that the user is attached to.</p>
    pub fn server_id(&self) -> &str {
        use std::ops::Deref;
        self.server_id.deref()
    }
    /// <p>A unique string that identifies a Transfer Family user.</p>
    pub fn user_name(&self) -> &str {
        use std::ops::Deref;
        self.user_name.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateUserOutput {
    /// Creates a new builder-style object to manufacture [`CreateUserOutput`](crate::operation::create_user::CreateUserOutput).
    pub fn builder() -> crate::operation::create_user::builders::CreateUserOutputBuilder {
        crate::operation::create_user::builders::CreateUserOutputBuilder::default()
    }
}

/// A builder for [`CreateUserOutput`](crate::operation::create_user::CreateUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateUserOutputBuilder {
    pub(crate) server_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateUserOutputBuilder {
    /// <p>The identifier of the server that the user is attached to.</p>
    /// This field is required.
    pub fn server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the server that the user is attached to.</p>
    pub fn set_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_id = input;
        self
    }
    /// <p>The identifier of the server that the user is attached to.</p>
    pub fn get_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_id
    }
    /// <p>A unique string that identifies a Transfer Family user.</p>
    /// This field is required.
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that identifies a Transfer Family user.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>A unique string that identifies a Transfer Family user.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateUserOutput`](crate::operation::create_user::CreateUserOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`server_id`](crate::operation::create_user::builders::CreateUserOutputBuilder::server_id)
    /// - [`user_name`](crate::operation::create_user::builders::CreateUserOutputBuilder::user_name)
    pub fn build(self) -> ::std::result::Result<crate::operation::create_user::CreateUserOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_user::CreateUserOutput {
            server_id: self.server_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "server_id",
                    "server_id was not specified but it is required when building CreateUserOutput",
                )
            })?,
            user_name: self.user_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "user_name",
                    "user_name was not specified but it is required when building CreateUserOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
