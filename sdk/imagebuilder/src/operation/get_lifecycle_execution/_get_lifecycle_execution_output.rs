// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLifecycleExecutionOutput {
    /// <p>Runtime details for the specified runtime instance of the lifecycle policy.</p>
    pub lifecycle_execution: ::std::option::Option<crate::types::LifecycleExecution>,
    _request_id: Option<String>,
}
impl GetLifecycleExecutionOutput {
    /// <p>Runtime details for the specified runtime instance of the lifecycle policy.</p>
    pub fn lifecycle_execution(&self) -> ::std::option::Option<&crate::types::LifecycleExecution> {
        self.lifecycle_execution.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetLifecycleExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLifecycleExecutionOutput {
    /// Creates a new builder-style object to manufacture [`GetLifecycleExecutionOutput`](crate::operation::get_lifecycle_execution::GetLifecycleExecutionOutput).
    pub fn builder() -> crate::operation::get_lifecycle_execution::builders::GetLifecycleExecutionOutputBuilder {
        crate::operation::get_lifecycle_execution::builders::GetLifecycleExecutionOutputBuilder::default()
    }
}

/// A builder for [`GetLifecycleExecutionOutput`](crate::operation::get_lifecycle_execution::GetLifecycleExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLifecycleExecutionOutputBuilder {
    pub(crate) lifecycle_execution: ::std::option::Option<crate::types::LifecycleExecution>,
    _request_id: Option<String>,
}
impl GetLifecycleExecutionOutputBuilder {
    /// <p>Runtime details for the specified runtime instance of the lifecycle policy.</p>
    pub fn lifecycle_execution(mut self, input: crate::types::LifecycleExecution) -> Self {
        self.lifecycle_execution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Runtime details for the specified runtime instance of the lifecycle policy.</p>
    pub fn set_lifecycle_execution(mut self, input: ::std::option::Option<crate::types::LifecycleExecution>) -> Self {
        self.lifecycle_execution = input;
        self
    }
    /// <p>Runtime details for the specified runtime instance of the lifecycle policy.</p>
    pub fn get_lifecycle_execution(&self) -> &::std::option::Option<crate::types::LifecycleExecution> {
        &self.lifecycle_execution
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLifecycleExecutionOutput`](crate::operation::get_lifecycle_execution::GetLifecycleExecutionOutput).
    pub fn build(self) -> crate::operation::get_lifecycle_execution::GetLifecycleExecutionOutput {
        crate::operation::get_lifecycle_execution::GetLifecycleExecutionOutput {
            lifecycle_execution: self.lifecycle_execution,
            _request_id: self._request_id,
        }
    }
}
