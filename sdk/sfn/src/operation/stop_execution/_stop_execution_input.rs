// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StopExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the execution to stop.</p>
    pub execution_arn: ::std::option::Option<::std::string::String>,
    /// <p>The error code of the failure.</p>
    pub error: ::std::option::Option<::std::string::String>,
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub cause: ::std::option::Option<::std::string::String>,
}
impl StopExecutionInput {
    /// <p>The Amazon Resource Name (ARN) of the execution to stop.</p>
    pub fn execution_arn(&self) -> ::std::option::Option<&str> {
        self.execution_arn.as_deref()
    }
    /// <p>The error code of the failure.</p>
    pub fn error(&self) -> ::std::option::Option<&str> {
        self.error.as_deref()
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn cause(&self) -> ::std::option::Option<&str> {
        self.cause.as_deref()
    }
}
impl ::std::fmt::Debug for StopExecutionInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StopExecutionInput");
        formatter.field("execution_arn", &self.execution_arn);
        formatter.field("error", &"*** Sensitive Data Redacted ***");
        formatter.field("cause", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl StopExecutionInput {
    /// Creates a new builder-style object to manufacture [`StopExecutionInput`](crate::operation::stop_execution::StopExecutionInput).
    pub fn builder() -> crate::operation::stop_execution::builders::StopExecutionInputBuilder {
        crate::operation::stop_execution::builders::StopExecutionInputBuilder::default()
    }
}

/// A builder for [`StopExecutionInput`](crate::operation::stop_execution::StopExecutionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StopExecutionInputBuilder {
    pub(crate) execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) error: ::std::option::Option<::std::string::String>,
    pub(crate) cause: ::std::option::Option<::std::string::String>,
}
impl StopExecutionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the execution to stop.</p>
    /// This field is required.
    pub fn execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution to stop.</p>
    pub fn set_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution to stop.</p>
    pub fn get_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_arn
    }
    /// <p>The error code of the failure.</p>
    pub fn error(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error code of the failure.</p>
    pub fn set_error(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error = input;
        self
    }
    /// <p>The error code of the failure.</p>
    pub fn get_error(&self) -> &::std::option::Option<::std::string::String> {
        &self.error
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn cause(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cause = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn set_cause(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cause = input;
        self
    }
    /// <p>A more detailed explanation of the cause of the failure.</p>
    pub fn get_cause(&self) -> &::std::option::Option<::std::string::String> {
        &self.cause
    }
    /// Consumes the builder and constructs a [`StopExecutionInput`](crate::operation::stop_execution::StopExecutionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_execution::StopExecutionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_execution::StopExecutionInput {
            execution_arn: self.execution_arn,
            error: self.error,
            cause: self.cause,
        })
    }
}
impl ::std::fmt::Debug for StopExecutionInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StopExecutionInputBuilder");
        formatter.field("execution_arn", &self.execution_arn);
        formatter.field("error", &"*** Sensitive Data Redacted ***");
        formatter.field("cause", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
