// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The order that compute environments are tried in for job placement within a queue. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower order integer value is tried for job placement first. Compute environments must be in the <code>VALID</code> state before you can associate them with a job queue. All of the compute environments must be either EC2 (<code>EC2</code> or <code>SPOT</code>) or Fargate (<code>FARGATE</code> or <code>FARGATE_SPOT</code>); Amazon EC2 and Fargate compute environments can't be mixed.</p><note>
/// <p>All compute environments that are associated with a job queue must share the same architecture. Batch doesn't support mixing compute environment architecture types in a single job queue.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ComputeEnvironmentOrder {
    /// <p>The order of the compute environment. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower <code>order</code> integer value is tried for job placement first.</p>
    pub order: ::std::option::Option<i32>,
    /// <p>The Amazon Resource Name (ARN) of the compute environment.</p>
    pub compute_environment: ::std::option::Option<::std::string::String>,
}
impl ComputeEnvironmentOrder {
    /// <p>The order of the compute environment. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower <code>order</code> integer value is tried for job placement first.</p>
    pub fn order(&self) -> ::std::option::Option<i32> {
        self.order
    }
    /// <p>The Amazon Resource Name (ARN) of the compute environment.</p>
    pub fn compute_environment(&self) -> ::std::option::Option<&str> {
        self.compute_environment.as_deref()
    }
}
impl ComputeEnvironmentOrder {
    /// Creates a new builder-style object to manufacture [`ComputeEnvironmentOrder`](crate::types::ComputeEnvironmentOrder).
    pub fn builder() -> crate::types::builders::ComputeEnvironmentOrderBuilder {
        crate::types::builders::ComputeEnvironmentOrderBuilder::default()
    }
}

/// A builder for [`ComputeEnvironmentOrder`](crate::types::ComputeEnvironmentOrder).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ComputeEnvironmentOrderBuilder {
    pub(crate) order: ::std::option::Option<i32>,
    pub(crate) compute_environment: ::std::option::Option<::std::string::String>,
}
impl ComputeEnvironmentOrderBuilder {
    /// <p>The order of the compute environment. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower <code>order</code> integer value is tried for job placement first.</p>
    /// This field is required.
    pub fn order(mut self, input: i32) -> Self {
        self.order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order of the compute environment. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower <code>order</code> integer value is tried for job placement first.</p>
    pub fn set_order(mut self, input: ::std::option::Option<i32>) -> Self {
        self.order = input;
        self
    }
    /// <p>The order of the compute environment. Compute environments are tried in ascending order. For example, if two compute environments are associated with a job queue, the compute environment with a lower <code>order</code> integer value is tried for job placement first.</p>
    pub fn get_order(&self) -> &::std::option::Option<i32> {
        &self.order
    }
    /// <p>The Amazon Resource Name (ARN) of the compute environment.</p>
    /// This field is required.
    pub fn compute_environment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compute_environment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the compute environment.</p>
    pub fn set_compute_environment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compute_environment = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the compute environment.</p>
    pub fn get_compute_environment(&self) -> &::std::option::Option<::std::string::String> {
        &self.compute_environment
    }
    /// Consumes the builder and constructs a [`ComputeEnvironmentOrder`](crate::types::ComputeEnvironmentOrder).
    pub fn build(self) -> crate::types::ComputeEnvironmentOrder {
        crate::types::ComputeEnvironmentOrder {
            order: self.order,
            compute_environment: self.compute_environment,
        }
    }
}
