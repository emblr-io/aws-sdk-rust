// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobInput {
    /// <p>The unique identifier you assigned to this job when it was created.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>Provides a view of the job document before and after the substitution parameters have been resolved with their exact values.</p>
    pub before_substitution: ::std::option::Option<bool>,
}
impl DescribeJobInput {
    /// <p>The unique identifier you assigned to this job when it was created.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>Provides a view of the job document before and after the substitution parameters have been resolved with their exact values.</p>
    pub fn before_substitution(&self) -> ::std::option::Option<bool> {
        self.before_substitution
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
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) before_substitution: ::std::option::Option<bool>,
}
impl DescribeJobInputBuilder {
    /// <p>The unique identifier you assigned to this job when it was created.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier you assigned to this job when it was created.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The unique identifier you assigned to this job when it was created.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>Provides a view of the job document before and after the substitution parameters have been resolved with their exact values.</p>
    pub fn before_substitution(mut self, input: bool) -> Self {
        self.before_substitution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides a view of the job document before and after the substitution parameters have been resolved with their exact values.</p>
    pub fn set_before_substitution(mut self, input: ::std::option::Option<bool>) -> Self {
        self.before_substitution = input;
        self
    }
    /// <p>Provides a view of the job document before and after the substitution parameters have been resolved with their exact values.</p>
    pub fn get_before_substitution(&self) -> &::std::option::Option<bool> {
        &self.before_substitution
    }
    /// Consumes the builder and constructs a [`DescribeJobInput`](crate::operation::describe_job::DescribeJobInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::describe_job::DescribeJobInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_job::DescribeJobInput {
            job_id: self.job_id,
            before_substitution: self.before_substitution,
        })
    }
}
