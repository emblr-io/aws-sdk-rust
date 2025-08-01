// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the results of your stop run attempt.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopRunOutput {
    /// <p>The run that was stopped.</p>
    pub run: ::std::option::Option<crate::types::Run>,
    _request_id: Option<String>,
}
impl StopRunOutput {
    /// <p>The run that was stopped.</p>
    pub fn run(&self) -> ::std::option::Option<&crate::types::Run> {
        self.run.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopRunOutput {
    /// Creates a new builder-style object to manufacture [`StopRunOutput`](crate::operation::stop_run::StopRunOutput).
    pub fn builder() -> crate::operation::stop_run::builders::StopRunOutputBuilder {
        crate::operation::stop_run::builders::StopRunOutputBuilder::default()
    }
}

/// A builder for [`StopRunOutput`](crate::operation::stop_run::StopRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopRunOutputBuilder {
    pub(crate) run: ::std::option::Option<crate::types::Run>,
    _request_id: Option<String>,
}
impl StopRunOutputBuilder {
    /// <p>The run that was stopped.</p>
    pub fn run(mut self, input: crate::types::Run) -> Self {
        self.run = ::std::option::Option::Some(input);
        self
    }
    /// <p>The run that was stopped.</p>
    pub fn set_run(mut self, input: ::std::option::Option<crate::types::Run>) -> Self {
        self.run = input;
        self
    }
    /// <p>The run that was stopped.</p>
    pub fn get_run(&self) -> &::std::option::Option<crate::types::Run> {
        &self.run
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopRunOutput`](crate::operation::stop_run::StopRunOutput).
    pub fn build(self) -> crate::operation::stop_run::StopRunOutput {
        crate::operation::stop_run::StopRunOutput {
            run: self.run,
            _request_id: self._request_id,
        }
    }
}
