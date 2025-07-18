// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobInput {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the job whose information you want to retrieve.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeJobInput {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The ID for the job whose information you want to retrieve.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
}
impl DescribeJobInput {
    /// Creates a new builder-style object to manufacture [`DescribeJobInput`](crate::operation::describe_job::DescribeJobInput).
    pub fn builder() -> crate::operation::describe_job::builders::DescribeJobInputBuilder {
        crate::operation::describe_job::builders::DescribeJobInputBuilder::default()
    }
}

/// A builder for [`DescribeJobInput`](crate::operation::describe_job::DescribeJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJobInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
}
impl DescribeJobInputBuilder {
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 Batch Operations job.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The ID for the job whose information you want to retrieve.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the job whose information you want to retrieve.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID for the job whose information you want to retrieve.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// Consumes the builder and constructs a [`DescribeJobInput`](crate::operation::describe_job::DescribeJobInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::describe_job::DescribeJobInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_job::DescribeJobInput {
            account_id: self.account_id,
            job_id: self.job_id,
        })
    }
}
