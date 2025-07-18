// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSimulationJobBatchInput {
    /// <p>The id of the batch to describe.</p>
    pub batch: ::std::option::Option<::std::string::String>,
}
impl DescribeSimulationJobBatchInput {
    /// <p>The id of the batch to describe.</p>
    pub fn batch(&self) -> ::std::option::Option<&str> {
        self.batch.as_deref()
    }
}
impl DescribeSimulationJobBatchInput {
    /// Creates a new builder-style object to manufacture [`DescribeSimulationJobBatchInput`](crate::operation::describe_simulation_job_batch::DescribeSimulationJobBatchInput).
    pub fn builder() -> crate::operation::describe_simulation_job_batch::builders::DescribeSimulationJobBatchInputBuilder {
        crate::operation::describe_simulation_job_batch::builders::DescribeSimulationJobBatchInputBuilder::default()
    }
}

/// A builder for [`DescribeSimulationJobBatchInput`](crate::operation::describe_simulation_job_batch::DescribeSimulationJobBatchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSimulationJobBatchInputBuilder {
    pub(crate) batch: ::std::option::Option<::std::string::String>,
}
impl DescribeSimulationJobBatchInputBuilder {
    /// <p>The id of the batch to describe.</p>
    /// This field is required.
    pub fn batch(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.batch = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The id of the batch to describe.</p>
    pub fn set_batch(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.batch = input;
        self
    }
    /// <p>The id of the batch to describe.</p>
    pub fn get_batch(&self) -> &::std::option::Option<::std::string::String> {
        &self.batch
    }
    /// Consumes the builder and constructs a [`DescribeSimulationJobBatchInput`](crate::operation::describe_simulation_job_batch::DescribeSimulationJobBatchInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_simulation_job_batch::DescribeSimulationJobBatchInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_simulation_job_batch::DescribeSimulationJobBatchInput { batch: self.batch })
    }
}
