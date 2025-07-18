// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Step taken during a cluster operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterOperationStep {
    /// <p>Information about the step and its status.</p>
    pub step_info: ::std::option::Option<crate::types::ClusterOperationStepInfo>,
    /// <p>The name of the step.</p>
    pub step_name: ::std::option::Option<::std::string::String>,
}
impl ClusterOperationStep {
    /// <p>Information about the step and its status.</p>
    pub fn step_info(&self) -> ::std::option::Option<&crate::types::ClusterOperationStepInfo> {
        self.step_info.as_ref()
    }
    /// <p>The name of the step.</p>
    pub fn step_name(&self) -> ::std::option::Option<&str> {
        self.step_name.as_deref()
    }
}
impl ClusterOperationStep {
    /// Creates a new builder-style object to manufacture [`ClusterOperationStep`](crate::types::ClusterOperationStep).
    pub fn builder() -> crate::types::builders::ClusterOperationStepBuilder {
        crate::types::builders::ClusterOperationStepBuilder::default()
    }
}

/// A builder for [`ClusterOperationStep`](crate::types::ClusterOperationStep).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterOperationStepBuilder {
    pub(crate) step_info: ::std::option::Option<crate::types::ClusterOperationStepInfo>,
    pub(crate) step_name: ::std::option::Option<::std::string::String>,
}
impl ClusterOperationStepBuilder {
    /// <p>Information about the step and its status.</p>
    pub fn step_info(mut self, input: crate::types::ClusterOperationStepInfo) -> Self {
        self.step_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the step and its status.</p>
    pub fn set_step_info(mut self, input: ::std::option::Option<crate::types::ClusterOperationStepInfo>) -> Self {
        self.step_info = input;
        self
    }
    /// <p>Information about the step and its status.</p>
    pub fn get_step_info(&self) -> &::std::option::Option<crate::types::ClusterOperationStepInfo> {
        &self.step_info
    }
    /// <p>The name of the step.</p>
    pub fn step_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the step.</p>
    pub fn set_step_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_name = input;
        self
    }
    /// <p>The name of the step.</p>
    pub fn get_step_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_name
    }
    /// Consumes the builder and constructs a [`ClusterOperationStep`](crate::types::ClusterOperationStep).
    pub fn build(self) -> crate::types::ClusterOperationStep {
        crate::types::ClusterOperationStep {
            step_info: self.step_info,
            step_name: self.step_name,
        }
    }
}
