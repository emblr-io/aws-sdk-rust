// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartExecutionOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies the execution.</p>
    pub execution_arn: ::std::string::String,
    /// <p>The date the execution is started.</p>
    pub start_date: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl StartExecutionOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies the execution.</p>
    pub fn execution_arn(&self) -> &str {
        use std::ops::Deref;
        self.execution_arn.deref()
    }
    /// <p>The date the execution is started.</p>
    pub fn start_date(&self) -> &::aws_smithy_types::DateTime {
        &self.start_date
    }
}
impl ::aws_types::request_id::RequestId for StartExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartExecutionOutput {
    /// Creates a new builder-style object to manufacture [`StartExecutionOutput`](crate::operation::start_execution::StartExecutionOutput).
    pub fn builder() -> crate::operation::start_execution::builders::StartExecutionOutputBuilder {
        crate::operation::start_execution::builders::StartExecutionOutputBuilder::default()
    }
}

/// A builder for [`StartExecutionOutput`](crate::operation::start_execution::StartExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartExecutionOutputBuilder {
    pub(crate) execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StartExecutionOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies the execution.</p>
    /// This field is required.
    pub fn execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution.</p>
    pub fn set_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the execution.</p>
    pub fn get_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_arn
    }
    /// <p>The date the execution is started.</p>
    /// This field is required.
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the execution is started.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The date the execution is started.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartExecutionOutput`](crate::operation::start_execution::StartExecutionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`execution_arn`](crate::operation::start_execution::builders::StartExecutionOutputBuilder::execution_arn)
    /// - [`start_date`](crate::operation::start_execution::builders::StartExecutionOutputBuilder::start_date)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_execution::StartExecutionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_execution::StartExecutionOutput {
            execution_arn: self.execution_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_arn",
                    "execution_arn was not specified but it is required when building StartExecutionOutput",
                )
            })?,
            start_date: self.start_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "start_date",
                    "start_date was not specified but it is required when building StartExecutionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
