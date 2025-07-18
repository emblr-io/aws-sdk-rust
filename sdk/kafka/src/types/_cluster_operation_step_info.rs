// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>State information about the operation step.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterOperationStepInfo {
    /// <p>The steps current status.</p>
    pub step_status: ::std::option::Option<::std::string::String>,
}
impl ClusterOperationStepInfo {
    /// <p>The steps current status.</p>
    pub fn step_status(&self) -> ::std::option::Option<&str> {
        self.step_status.as_deref()
    }
}
impl ClusterOperationStepInfo {
    /// Creates a new builder-style object to manufacture [`ClusterOperationStepInfo`](crate::types::ClusterOperationStepInfo).
    pub fn builder() -> crate::types::builders::ClusterOperationStepInfoBuilder {
        crate::types::builders::ClusterOperationStepInfoBuilder::default()
    }
}

/// A builder for [`ClusterOperationStepInfo`](crate::types::ClusterOperationStepInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterOperationStepInfoBuilder {
    pub(crate) step_status: ::std::option::Option<::std::string::String>,
}
impl ClusterOperationStepInfoBuilder {
    /// <p>The steps current status.</p>
    pub fn step_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The steps current status.</p>
    pub fn set_step_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_status = input;
        self
    }
    /// <p>The steps current status.</p>
    pub fn get_step_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_status
    }
    /// Consumes the builder and constructs a [`ClusterOperationStepInfo`](crate::types::ClusterOperationStepInfo).
    pub fn build(self) -> crate::types::ClusterOperationStepInfo {
        crate::types::ClusterOperationStepInfo {
            step_status: self.step_status,
        }
    }
}
