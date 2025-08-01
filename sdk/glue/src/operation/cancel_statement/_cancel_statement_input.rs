// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelStatementInput {
    /// <p>The Session ID of the statement to be cancelled.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the statement to be cancelled.</p>
    pub id: ::std::option::Option<i32>,
    /// <p>The origin of the request to cancel the statement.</p>
    pub request_origin: ::std::option::Option<::std::string::String>,
}
impl CancelStatementInput {
    /// <p>The Session ID of the statement to be cancelled.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
    /// <p>The ID of the statement to be cancelled.</p>
    pub fn id(&self) -> ::std::option::Option<i32> {
        self.id
    }
    /// <p>The origin of the request to cancel the statement.</p>
    pub fn request_origin(&self) -> ::std::option::Option<&str> {
        self.request_origin.as_deref()
    }
}
impl CancelStatementInput {
    /// Creates a new builder-style object to manufacture [`CancelStatementInput`](crate::operation::cancel_statement::CancelStatementInput).
    pub fn builder() -> crate::operation::cancel_statement::builders::CancelStatementInputBuilder {
        crate::operation::cancel_statement::builders::CancelStatementInputBuilder::default()
    }
}

/// A builder for [`CancelStatementInput`](crate::operation::cancel_statement::CancelStatementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelStatementInputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<i32>,
    pub(crate) request_origin: ::std::option::Option<::std::string::String>,
}
impl CancelStatementInputBuilder {
    /// <p>The Session ID of the statement to be cancelled.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Session ID of the statement to be cancelled.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The Session ID of the statement to be cancelled.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The ID of the statement to be cancelled.</p>
    /// This field is required.
    pub fn id(mut self, input: i32) -> Self {
        self.id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the statement to be cancelled.</p>
    pub fn set_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the statement to be cancelled.</p>
    pub fn get_id(&self) -> &::std::option::Option<i32> {
        &self.id
    }
    /// <p>The origin of the request to cancel the statement.</p>
    pub fn request_origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The origin of the request to cancel the statement.</p>
    pub fn set_request_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_origin = input;
        self
    }
    /// <p>The origin of the request to cancel the statement.</p>
    pub fn get_request_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_origin
    }
    /// Consumes the builder and constructs a [`CancelStatementInput`](crate::operation::cancel_statement::CancelStatementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_statement::CancelStatementInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_statement::CancelStatementInput {
            session_id: self.session_id,
            id: self.id,
            request_origin: self.request_origin,
        })
    }
}
