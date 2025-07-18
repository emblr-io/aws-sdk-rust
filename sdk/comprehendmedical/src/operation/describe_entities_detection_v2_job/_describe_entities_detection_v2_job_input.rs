// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEntitiesDetectionV2JobInput {
    /// <p>The identifier that Amazon Comprehend Medical generated for the job. The <code>StartEntitiesDetectionV2Job</code> operation returns this identifier in its response.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeEntitiesDetectionV2JobInput {
    /// <p>The identifier that Amazon Comprehend Medical generated for the job. The <code>StartEntitiesDetectionV2Job</code> operation returns this identifier in its response.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl DescribeEntitiesDetectionV2JobInput {
    /// Creates a new builder-style object to manufacture [`DescribeEntitiesDetectionV2JobInput`](crate::operation::describe_entities_detection_v2_job::DescribeEntitiesDetectionV2JobInput).
    pub fn builder() -> crate::operation::describe_entities_detection_v2_job::builders::DescribeEntitiesDetectionV2JobInputBuilder {
        crate::operation::describe_entities_detection_v2_job::builders::DescribeEntitiesDetectionV2JobInputBuilder::default()
    }
}

/// A builder for [`DescribeEntitiesDetectionV2JobInput`](crate::operation::describe_entities_detection_v2_job::DescribeEntitiesDetectionV2JobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEntitiesDetectionV2JobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeEntitiesDetectionV2JobInputBuilder {
    /// <p>The identifier that Amazon Comprehend Medical generated for the job. The <code>StartEntitiesDetectionV2Job</code> operation returns this identifier in its response.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier that Amazon Comprehend Medical generated for the job. The <code>StartEntitiesDetectionV2Job</code> operation returns this identifier in its response.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier that Amazon Comprehend Medical generated for the job. The <code>StartEntitiesDetectionV2Job</code> operation returns this identifier in its response.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`DescribeEntitiesDetectionV2JobInput`](crate::operation::describe_entities_detection_v2_job::DescribeEntitiesDetectionV2JobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_entities_detection_v2_job::DescribeEntitiesDetectionV2JobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_entities_detection_v2_job::DescribeEntitiesDetectionV2JobInput { job_id: self.job_id })
    }
}
