// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the steps in the workflow, as well as the steps to execute in case of any errors during workflow execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecutionResults {
    /// <p>Specifies the details for the steps that are in the specified workflow.</p>
    pub steps: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>,
    /// <p>Specifies the steps (actions) to take if errors are encountered during execution of the workflow.</p>
    pub on_exception_steps: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>,
}
impl ExecutionResults {
    /// <p>Specifies the details for the steps that are in the specified workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.steps.is_none()`.
    pub fn steps(&self) -> &[crate::types::ExecutionStepResult] {
        self.steps.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the steps (actions) to take if errors are encountered during execution of the workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.on_exception_steps.is_none()`.
    pub fn on_exception_steps(&self) -> &[crate::types::ExecutionStepResult] {
        self.on_exception_steps.as_deref().unwrap_or_default()
    }
}
impl ExecutionResults {
    /// Creates a new builder-style object to manufacture [`ExecutionResults`](crate::types::ExecutionResults).
    pub fn builder() -> crate::types::builders::ExecutionResultsBuilder {
        crate::types::builders::ExecutionResultsBuilder::default()
    }
}

/// A builder for [`ExecutionResults`](crate::types::ExecutionResults).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecutionResultsBuilder {
    pub(crate) steps: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>,
    pub(crate) on_exception_steps: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>,
}
impl ExecutionResultsBuilder {
    /// Appends an item to `steps`.
    ///
    /// To override the contents of this collection use [`set_steps`](Self::set_steps).
    ///
    /// <p>Specifies the details for the steps that are in the specified workflow.</p>
    pub fn steps(mut self, input: crate::types::ExecutionStepResult) -> Self {
        let mut v = self.steps.unwrap_or_default();
        v.push(input);
        self.steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the details for the steps that are in the specified workflow.</p>
    pub fn set_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>) -> Self {
        self.steps = input;
        self
    }
    /// <p>Specifies the details for the steps that are in the specified workflow.</p>
    pub fn get_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>> {
        &self.steps
    }
    /// Appends an item to `on_exception_steps`.
    ///
    /// To override the contents of this collection use [`set_on_exception_steps`](Self::set_on_exception_steps).
    ///
    /// <p>Specifies the steps (actions) to take if errors are encountered during execution of the workflow.</p>
    pub fn on_exception_steps(mut self, input: crate::types::ExecutionStepResult) -> Self {
        let mut v = self.on_exception_steps.unwrap_or_default();
        v.push(input);
        self.on_exception_steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the steps (actions) to take if errors are encountered during execution of the workflow.</p>
    pub fn set_on_exception_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>>) -> Self {
        self.on_exception_steps = input;
        self
    }
    /// <p>Specifies the steps (actions) to take if errors are encountered during execution of the workflow.</p>
    pub fn get_on_exception_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExecutionStepResult>> {
        &self.on_exception_steps
    }
    /// Consumes the builder and constructs a [`ExecutionResults`](crate::types::ExecutionResults).
    pub fn build(self) -> crate::types::ExecutionResults {
        crate::types::ExecutionResults {
            steps: self.steps,
            on_exception_steps: self.on_exception_steps,
        }
    }
}
