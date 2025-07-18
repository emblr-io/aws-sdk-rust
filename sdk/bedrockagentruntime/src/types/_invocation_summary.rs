// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about an invocation in a session. For more information about sessions, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/sessions.html">Store and retrieve conversation history and context with Amazon Bedrock sessions</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InvocationSummary {
    /// <p>The unique identifier for the session associated with the invocation.</p>
    pub session_id: ::std::string::String,
    /// <p>A unique identifier for the invocation in UUID format.</p>
    pub invocation_id: ::std::string::String,
    /// <p>The timestamp for when the invocation was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
}
impl InvocationSummary {
    /// <p>The unique identifier for the session associated with the invocation.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
    /// <p>A unique identifier for the invocation in UUID format.</p>
    pub fn invocation_id(&self) -> &str {
        use std::ops::Deref;
        self.invocation_id.deref()
    }
    /// <p>The timestamp for when the invocation was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
}
impl InvocationSummary {
    /// Creates a new builder-style object to manufacture [`InvocationSummary`](crate::types::InvocationSummary).
    pub fn builder() -> crate::types::builders::InvocationSummaryBuilder {
        crate::types::builders::InvocationSummaryBuilder::default()
    }
}

/// A builder for [`InvocationSummary`](crate::types::InvocationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvocationSummaryBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) invocation_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl InvocationSummaryBuilder {
    /// <p>The unique identifier for the session associated with the invocation.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the session associated with the invocation.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier for the session associated with the invocation.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>A unique identifier for the invocation in UUID format.</p>
    /// This field is required.
    pub fn invocation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invocation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the invocation in UUID format.</p>
    pub fn set_invocation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invocation_id = input;
        self
    }
    /// <p>A unique identifier for the invocation in UUID format.</p>
    pub fn get_invocation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invocation_id
    }
    /// <p>The timestamp for when the invocation was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the invocation was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp for when the invocation was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// Consumes the builder and constructs a [`InvocationSummary`](crate::types::InvocationSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::types::builders::InvocationSummaryBuilder::session_id)
    /// - [`invocation_id`](crate::types::builders::InvocationSummaryBuilder::invocation_id)
    /// - [`created_at`](crate::types::builders::InvocationSummaryBuilder::created_at)
    pub fn build(self) -> ::std::result::Result<crate::types::InvocationSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InvocationSummary {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building InvocationSummary",
                )
            })?,
            invocation_id: self.invocation_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "invocation_id",
                    "invocation_id was not specified but it is required when building InvocationSummary",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building InvocationSummary",
                )
            })?,
        })
    }
}
