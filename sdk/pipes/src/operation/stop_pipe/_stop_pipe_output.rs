// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopPipeOutput {
    /// <p>The ARN of the pipe.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the pipe.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The state the pipe should be in.</p>
    pub desired_state: ::std::option::Option<crate::types::RequestedPipeState>,
    /// <p>The state the pipe is in.</p>
    pub current_state: ::std::option::Option<crate::types::PipeState>,
    /// <p>The time the pipe was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>When the pipe was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StopPipeOutput {
    /// <p>The ARN of the pipe.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the pipe.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The state the pipe should be in.</p>
    pub fn desired_state(&self) -> ::std::option::Option<&crate::types::RequestedPipeState> {
        self.desired_state.as_ref()
    }
    /// <p>The state the pipe is in.</p>
    pub fn current_state(&self) -> ::std::option::Option<&crate::types::PipeState> {
        self.current_state.as_ref()
    }
    /// <p>The time the pipe was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>When the pipe was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopPipeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopPipeOutput {
    /// Creates a new builder-style object to manufacture [`StopPipeOutput`](crate::operation::stop_pipe::StopPipeOutput).
    pub fn builder() -> crate::operation::stop_pipe::builders::StopPipeOutputBuilder {
        crate::operation::stop_pipe::builders::StopPipeOutputBuilder::default()
    }
}

/// A builder for [`StopPipeOutput`](crate::operation::stop_pipe::StopPipeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopPipeOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) desired_state: ::std::option::Option<crate::types::RequestedPipeState>,
    pub(crate) current_state: ::std::option::Option<crate::types::PipeState>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StopPipeOutputBuilder {
    /// <p>The ARN of the pipe.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the pipe.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the pipe.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the pipe.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the pipe.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the pipe.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The state the pipe should be in.</p>
    pub fn desired_state(mut self, input: crate::types::RequestedPipeState) -> Self {
        self.desired_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state the pipe should be in.</p>
    pub fn set_desired_state(mut self, input: ::std::option::Option<crate::types::RequestedPipeState>) -> Self {
        self.desired_state = input;
        self
    }
    /// <p>The state the pipe should be in.</p>
    pub fn get_desired_state(&self) -> &::std::option::Option<crate::types::RequestedPipeState> {
        &self.desired_state
    }
    /// <p>The state the pipe is in.</p>
    pub fn current_state(mut self, input: crate::types::PipeState) -> Self {
        self.current_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state the pipe is in.</p>
    pub fn set_current_state(mut self, input: ::std::option::Option<crate::types::PipeState>) -> Self {
        self.current_state = input;
        self
    }
    /// <p>The state the pipe is in.</p>
    pub fn get_current_state(&self) -> &::std::option::Option<crate::types::PipeState> {
        &self.current_state
    }
    /// <p>The time the pipe was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the pipe was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time the pipe was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>When the pipe was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the pipe was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>When the pipe was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopPipeOutput`](crate::operation::stop_pipe::StopPipeOutput).
    pub fn build(self) -> crate::operation::stop_pipe::StopPipeOutput {
        crate::operation::stop_pipe::StopPipeOutput {
            arn: self.arn,
            name: self.name,
            desired_state: self.desired_state,
            current_state: self.current_state,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            _request_id: self._request_id,
        }
    }
}
