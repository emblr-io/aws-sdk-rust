// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSessionInput {
    /// <p>Amazon Resource Name (ARN) for the session.</p>
    pub session_arn: ::std::option::Option<::std::string::String>,
}
impl GetSessionInput {
    /// <p>Amazon Resource Name (ARN) for the session.</p>
    pub fn session_arn(&self) -> ::std::option::Option<&str> {
        self.session_arn.as_deref()
    }
}
impl GetSessionInput {
    /// Creates a new builder-style object to manufacture [`GetSessionInput`](crate::operation::get_session::GetSessionInput).
    pub fn builder() -> crate::operation::get_session::builders::GetSessionInputBuilder {
        crate::operation::get_session::builders::GetSessionInputBuilder::default()
    }
}

/// A builder for [`GetSessionInput`](crate::operation::get_session::GetSessionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSessionInputBuilder {
    pub(crate) session_arn: ::std::option::Option<::std::string::String>,
}
impl GetSessionInputBuilder {
    /// <p>Amazon Resource Name (ARN) for the session.</p>
    /// This field is required.
    pub fn session_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) for the session.</p>
    pub fn set_session_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) for the session.</p>
    pub fn get_session_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_arn
    }
    /// Consumes the builder and constructs a [`GetSessionInput`](crate::operation::get_session::GetSessionInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_session::GetSessionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_session::GetSessionInput {
            session_arn: self.session_arn,
        })
    }
}
