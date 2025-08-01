// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStatementsInput {
    /// <p>The Session ID of the statements.</p>
    pub session_id: ::std::option::Option<::std::string::String>,
    /// <p>The origin of the request to list statements.</p>
    pub request_origin: ::std::option::Option<::std::string::String>,
    /// <p>A continuation token, if this is a continuation call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListStatementsInput {
    /// <p>The Session ID of the statements.</p>
    pub fn session_id(&self) -> ::std::option::Option<&str> {
        self.session_id.as_deref()
    }
    /// <p>The origin of the request to list statements.</p>
    pub fn request_origin(&self) -> ::std::option::Option<&str> {
        self.request_origin.as_deref()
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListStatementsInput {
    /// Creates a new builder-style object to manufacture [`ListStatementsInput`](crate::operation::list_statements::ListStatementsInput).
    pub fn builder() -> crate::operation::list_statements::builders::ListStatementsInputBuilder {
        crate::operation::list_statements::builders::ListStatementsInputBuilder::default()
    }
}

/// A builder for [`ListStatementsInput`](crate::operation::list_statements::ListStatementsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStatementsInputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) request_origin: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListStatementsInputBuilder {
    /// <p>The Session ID of the statements.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Session ID of the statements.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The Session ID of the statements.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The origin of the request to list statements.</p>
    pub fn request_origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The origin of the request to list statements.</p>
    pub fn set_request_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_origin = input;
        self
    }
    /// <p>The origin of the request to list statements.</p>
    pub fn get_request_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_origin
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is a continuation call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListStatementsInput`](crate::operation::list_statements::ListStatementsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_statements::ListStatementsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_statements::ListStatementsInput {
            session_id: self.session_id,
            request_origin: self.request_origin,
            next_token: self.next_token,
        })
    }
}
