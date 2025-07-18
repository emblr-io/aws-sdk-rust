// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopExperimentInput {
    /// <p>The name or ARN of the project that contains the experiment to stop.</p>
    pub project: ::std::option::Option<::std::string::String>,
    /// <p>The name of the experiment to stop.</p>
    pub experiment: ::std::option::Option<::std::string::String>,
    /// <p>Specify whether the experiment is to be considered <code>COMPLETED</code> or <code>CANCELLED</code> after it stops.</p>
    pub desired_state: ::std::option::Option<crate::types::ExperimentStopDesiredState>,
    /// <p>A string that describes why you are stopping the experiment.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl StopExperimentInput {
    /// <p>The name or ARN of the project that contains the experiment to stop.</p>
    pub fn project(&self) -> ::std::option::Option<&str> {
        self.project.as_deref()
    }
    /// <p>The name of the experiment to stop.</p>
    pub fn experiment(&self) -> ::std::option::Option<&str> {
        self.experiment.as_deref()
    }
    /// <p>Specify whether the experiment is to be considered <code>COMPLETED</code> or <code>CANCELLED</code> after it stops.</p>
    pub fn desired_state(&self) -> ::std::option::Option<&crate::types::ExperimentStopDesiredState> {
        self.desired_state.as_ref()
    }
    /// <p>A string that describes why you are stopping the experiment.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl StopExperimentInput {
    /// Creates a new builder-style object to manufacture [`StopExperimentInput`](crate::operation::stop_experiment::StopExperimentInput).
    pub fn builder() -> crate::operation::stop_experiment::builders::StopExperimentInputBuilder {
        crate::operation::stop_experiment::builders::StopExperimentInputBuilder::default()
    }
}

/// A builder for [`StopExperimentInput`](crate::operation::stop_experiment::StopExperimentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopExperimentInputBuilder {
    pub(crate) project: ::std::option::Option<::std::string::String>,
    pub(crate) experiment: ::std::option::Option<::std::string::String>,
    pub(crate) desired_state: ::std::option::Option<crate::types::ExperimentStopDesiredState>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl StopExperimentInputBuilder {
    /// <p>The name or ARN of the project that contains the experiment to stop.</p>
    /// This field is required.
    pub fn project(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the project that contains the experiment to stop.</p>
    pub fn set_project(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project = input;
        self
    }
    /// <p>The name or ARN of the project that contains the experiment to stop.</p>
    pub fn get_project(&self) -> &::std::option::Option<::std::string::String> {
        &self.project
    }
    /// <p>The name of the experiment to stop.</p>
    /// This field is required.
    pub fn experiment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.experiment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the experiment to stop.</p>
    pub fn set_experiment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.experiment = input;
        self
    }
    /// <p>The name of the experiment to stop.</p>
    pub fn get_experiment(&self) -> &::std::option::Option<::std::string::String> {
        &self.experiment
    }
    /// <p>Specify whether the experiment is to be considered <code>COMPLETED</code> or <code>CANCELLED</code> after it stops.</p>
    pub fn desired_state(mut self, input: crate::types::ExperimentStopDesiredState) -> Self {
        self.desired_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify whether the experiment is to be considered <code>COMPLETED</code> or <code>CANCELLED</code> after it stops.</p>
    pub fn set_desired_state(mut self, input: ::std::option::Option<crate::types::ExperimentStopDesiredState>) -> Self {
        self.desired_state = input;
        self
    }
    /// <p>Specify whether the experiment is to be considered <code>COMPLETED</code> or <code>CANCELLED</code> after it stops.</p>
    pub fn get_desired_state(&self) -> &::std::option::Option<crate::types::ExperimentStopDesiredState> {
        &self.desired_state
    }
    /// <p>A string that describes why you are stopping the experiment.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that describes why you are stopping the experiment.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>A string that describes why you are stopping the experiment.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`StopExperimentInput`](crate::operation::stop_experiment::StopExperimentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_experiment::StopExperimentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_experiment::StopExperimentInput {
            project: self.project,
            experiment: self.experiment,
            desired_state: self.desired_state,
            reason: self.reason,
        })
    }
}
