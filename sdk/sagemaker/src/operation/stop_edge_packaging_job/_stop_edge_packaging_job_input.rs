// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopEdgePackagingJobInput {
    /// <p>The name of the edge packaging job.</p>
    pub edge_packaging_job_name: ::std::option::Option<::std::string::String>,
}
impl StopEdgePackagingJobInput {
    /// <p>The name of the edge packaging job.</p>
    pub fn edge_packaging_job_name(&self) -> ::std::option::Option<&str> {
        self.edge_packaging_job_name.as_deref()
    }
}
impl StopEdgePackagingJobInput {
    /// Creates a new builder-style object to manufacture [`StopEdgePackagingJobInput`](crate::operation::stop_edge_packaging_job::StopEdgePackagingJobInput).
    pub fn builder() -> crate::operation::stop_edge_packaging_job::builders::StopEdgePackagingJobInputBuilder {
        crate::operation::stop_edge_packaging_job::builders::StopEdgePackagingJobInputBuilder::default()
    }
}

/// A builder for [`StopEdgePackagingJobInput`](crate::operation::stop_edge_packaging_job::StopEdgePackagingJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopEdgePackagingJobInputBuilder {
    pub(crate) edge_packaging_job_name: ::std::option::Option<::std::string::String>,
}
impl StopEdgePackagingJobInputBuilder {
    /// <p>The name of the edge packaging job.</p>
    /// This field is required.
    pub fn edge_packaging_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.edge_packaging_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the edge packaging job.</p>
    pub fn set_edge_packaging_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.edge_packaging_job_name = input;
        self
    }
    /// <p>The name of the edge packaging job.</p>
    pub fn get_edge_packaging_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.edge_packaging_job_name
    }
    /// Consumes the builder and constructs a [`StopEdgePackagingJobInput`](crate::operation::stop_edge_packaging_job::StopEdgePackagingJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_edge_packaging_job::StopEdgePackagingJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::stop_edge_packaging_job::StopEdgePackagingJobInput {
            edge_packaging_job_name: self.edge_packaging_job_name,
        })
    }
}
