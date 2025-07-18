// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RestartSimulationJobOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RestartSimulationJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RestartSimulationJobOutput {
    /// Creates a new builder-style object to manufacture [`RestartSimulationJobOutput`](crate::operation::restart_simulation_job::RestartSimulationJobOutput).
    pub fn builder() -> crate::operation::restart_simulation_job::builders::RestartSimulationJobOutputBuilder {
        crate::operation::restart_simulation_job::builders::RestartSimulationJobOutputBuilder::default()
    }
}

/// A builder for [`RestartSimulationJobOutput`](crate::operation::restart_simulation_job::RestartSimulationJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RestartSimulationJobOutputBuilder {
    _request_id: Option<String>,
}
impl RestartSimulationJobOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RestartSimulationJobOutput`](crate::operation::restart_simulation_job::RestartSimulationJobOutput).
    pub fn build(self) -> crate::operation::restart_simulation_job::RestartSimulationJobOutput {
        crate::operation::restart_simulation_job::RestartSimulationJobOutput {
            _request_id: self._request_id,
        }
    }
}
