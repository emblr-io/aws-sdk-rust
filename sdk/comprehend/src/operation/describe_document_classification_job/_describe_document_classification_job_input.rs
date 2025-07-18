// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDocumentClassificationJobInput {
    /// <p>The identifier that Amazon Comprehend generated for the job. The <code>StartDocumentClassificationJob</code> operation returns this identifier in its response.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDocumentClassificationJobInput {
    /// <p>The identifier that Amazon Comprehend generated for the job. The <code>StartDocumentClassificationJob</code> operation returns this identifier in its response.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl DescribeDocumentClassificationJobInput {
    /// Creates a new builder-style object to manufacture [`DescribeDocumentClassificationJobInput`](crate::operation::describe_document_classification_job::DescribeDocumentClassificationJobInput).
    pub fn builder() -> crate::operation::describe_document_classification_job::builders::DescribeDocumentClassificationJobInputBuilder {
        crate::operation::describe_document_classification_job::builders::DescribeDocumentClassificationJobInputBuilder::default()
    }
}

/// A builder for [`DescribeDocumentClassificationJobInput`](crate::operation::describe_document_classification_job::DescribeDocumentClassificationJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDocumentClassificationJobInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDocumentClassificationJobInputBuilder {
    /// <p>The identifier that Amazon Comprehend generated for the job. The <code>StartDocumentClassificationJob</code> operation returns this identifier in its response.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier that Amazon Comprehend generated for the job. The <code>StartDocumentClassificationJob</code> operation returns this identifier in its response.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The identifier that Amazon Comprehend generated for the job. The <code>StartDocumentClassificationJob</code> operation returns this identifier in its response.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`DescribeDocumentClassificationJobInput`](crate::operation::describe_document_classification_job::DescribeDocumentClassificationJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_document_classification_job::DescribeDocumentClassificationJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_document_classification_job::DescribeDocumentClassificationJobInput { job_id: self.job_id },
        )
    }
}
