// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The pipeline execution to filter on.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipelineExecutionFilter {
    /// <p>Filter for pipeline executions where the stage was successful in the current pipeline version.</p>
    pub succeeded_in_stage: ::std::option::Option<crate::types::SucceededInStageFilter>,
}
impl PipelineExecutionFilter {
    /// <p>Filter for pipeline executions where the stage was successful in the current pipeline version.</p>
    pub fn succeeded_in_stage(&self) -> ::std::option::Option<&crate::types::SucceededInStageFilter> {
        self.succeeded_in_stage.as_ref()
    }
}
impl PipelineExecutionFilter {
    /// Creates a new builder-style object to manufacture [`PipelineExecutionFilter`](crate::types::PipelineExecutionFilter).
    pub fn builder() -> crate::types::builders::PipelineExecutionFilterBuilder {
        crate::types::builders::PipelineExecutionFilterBuilder::default()
    }
}

/// A builder for [`PipelineExecutionFilter`](crate::types::PipelineExecutionFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipelineExecutionFilterBuilder {
    pub(crate) succeeded_in_stage: ::std::option::Option<crate::types::SucceededInStageFilter>,
}
impl PipelineExecutionFilterBuilder {
    /// <p>Filter for pipeline executions where the stage was successful in the current pipeline version.</p>
    pub fn succeeded_in_stage(mut self, input: crate::types::SucceededInStageFilter) -> Self {
        self.succeeded_in_stage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter for pipeline executions where the stage was successful in the current pipeline version.</p>
    pub fn set_succeeded_in_stage(mut self, input: ::std::option::Option<crate::types::SucceededInStageFilter>) -> Self {
        self.succeeded_in_stage = input;
        self
    }
    /// <p>Filter for pipeline executions where the stage was successful in the current pipeline version.</p>
    pub fn get_succeeded_in_stage(&self) -> &::std::option::Option<crate::types::SucceededInStageFilter> {
        &self.succeeded_in_stage
    }
    /// Consumes the builder and constructs a [`PipelineExecutionFilter`](crate::types::PipelineExecutionFilter).
    pub fn build(self) -> crate::types::PipelineExecutionFilter {
        crate::types::PipelineExecutionFilter {
            succeeded_in_stage: self.succeeded_in_stage,
        }
    }
}
