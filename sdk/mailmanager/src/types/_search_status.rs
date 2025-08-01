// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The current status of an archive search job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchStatus {
    /// <p>The timestamp of when the search was submitted.</p>
    pub submission_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp of when the search completed (if finished).</p>
    pub completion_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current state of the search job.</p>
    pub state: ::std::option::Option<crate::types::SearchState>,
    /// <p>An error message if the search failed.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl SearchStatus {
    /// <p>The timestamp of when the search was submitted.</p>
    pub fn submission_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.submission_timestamp.as_ref()
    }
    /// <p>The timestamp of when the search completed (if finished).</p>
    pub fn completion_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.completion_timestamp.as_ref()
    }
    /// <p>The current state of the search job.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::SearchState> {
        self.state.as_ref()
    }
    /// <p>An error message if the search failed.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl SearchStatus {
    /// Creates a new builder-style object to manufacture [`SearchStatus`](crate::types::SearchStatus).
    pub fn builder() -> crate::types::builders::SearchStatusBuilder {
        crate::types::builders::SearchStatusBuilder::default()
    }
}

/// A builder for [`SearchStatus`](crate::types::SearchStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchStatusBuilder {
    pub(crate) submission_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) completion_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::SearchState>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl SearchStatusBuilder {
    /// <p>The timestamp of when the search was submitted.</p>
    pub fn submission_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.submission_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the search was submitted.</p>
    pub fn set_submission_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.submission_timestamp = input;
        self
    }
    /// <p>The timestamp of when the search was submitted.</p>
    pub fn get_submission_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.submission_timestamp
    }
    /// <p>The timestamp of when the search completed (if finished).</p>
    pub fn completion_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.completion_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the search completed (if finished).</p>
    pub fn set_completion_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.completion_timestamp = input;
        self
    }
    /// <p>The timestamp of when the search completed (if finished).</p>
    pub fn get_completion_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.completion_timestamp
    }
    /// <p>The current state of the search job.</p>
    pub fn state(mut self, input: crate::types::SearchState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the search job.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::SearchState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the search job.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::SearchState> {
        &self.state
    }
    /// <p>An error message if the search failed.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An error message if the search failed.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>An error message if the search failed.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`SearchStatus`](crate::types::SearchStatus).
    pub fn build(self) -> crate::types::SearchStatus {
        crate::types::SearchStatus {
            submission_timestamp: self.submission_timestamp,
            completion_timestamp: self.completion_timestamp,
            state: self.state,
            error_message: self.error_message,
        }
    }
}
