// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents information about the run of a condition for a stage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StageConditionsExecution {
    /// <p>The status of a run of a condition for a stage.</p>
    pub status: ::std::option::Option<crate::types::ConditionExecutionStatus>,
    /// <p>A summary of the run of the condition for a stage.</p>
    pub summary: ::std::option::Option<::std::string::String>,
}
impl StageConditionsExecution {
    /// <p>The status of a run of a condition for a stage.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ConditionExecutionStatus> {
        self.status.as_ref()
    }
    /// <p>A summary of the run of the condition for a stage.</p>
    pub fn summary(&self) -> ::std::option::Option<&str> {
        self.summary.as_deref()
    }
}
impl StageConditionsExecution {
    /// Creates a new builder-style object to manufacture [`StageConditionsExecution`](crate::types::StageConditionsExecution).
    pub fn builder() -> crate::types::builders::StageConditionsExecutionBuilder {
        crate::types::builders::StageConditionsExecutionBuilder::default()
    }
}

/// A builder for [`StageConditionsExecution`](crate::types::StageConditionsExecution).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StageConditionsExecutionBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ConditionExecutionStatus>,
    pub(crate) summary: ::std::option::Option<::std::string::String>,
}
impl StageConditionsExecutionBuilder {
    /// <p>The status of a run of a condition for a stage.</p>
    pub fn status(mut self, input: crate::types::ConditionExecutionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a run of a condition for a stage.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ConditionExecutionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a run of a condition for a stage.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ConditionExecutionStatus> {
        &self.status
    }
    /// <p>A summary of the run of the condition for a stage.</p>
    pub fn summary(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.summary = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A summary of the run of the condition for a stage.</p>
    pub fn set_summary(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.summary = input;
        self
    }
    /// <p>A summary of the run of the condition for a stage.</p>
    pub fn get_summary(&self) -> &::std::option::Option<::std::string::String> {
        &self.summary
    }
    /// Consumes the builder and constructs a [`StageConditionsExecution`](crate::types::StageConditionsExecution).
    pub fn build(self) -> crate::types::StageConditionsExecution {
        crate::types::StageConditionsExecution {
            status: self.status,
            summary: self.summary,
        }
    }
}
