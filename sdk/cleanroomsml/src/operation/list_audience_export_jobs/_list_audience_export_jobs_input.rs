// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAudienceExportJobsInput {
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum size of the results that is returned per call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The Amazon Resource Name (ARN) of the audience generation job that you are interested in.</p>
    pub audience_generation_job_arn: ::std::option::Option<::std::string::String>,
}
impl ListAudienceExportJobsInput {
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum size of the results that is returned per call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The Amazon Resource Name (ARN) of the audience generation job that you are interested in.</p>
    pub fn audience_generation_job_arn(&self) -> ::std::option::Option<&str> {
        self.audience_generation_job_arn.as_deref()
    }
}
impl ListAudienceExportJobsInput {
    /// Creates a new builder-style object to manufacture [`ListAudienceExportJobsInput`](crate::operation::list_audience_export_jobs::ListAudienceExportJobsInput).
    pub fn builder() -> crate::operation::list_audience_export_jobs::builders::ListAudienceExportJobsInputBuilder {
        crate::operation::list_audience_export_jobs::builders::ListAudienceExportJobsInputBuilder::default()
    }
}

/// A builder for [`ListAudienceExportJobsInput`](crate::operation::list_audience_export_jobs::ListAudienceExportJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAudienceExportJobsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) audience_generation_job_arn: ::std::option::Option<::std::string::String>,
}
impl ListAudienceExportJobsInputBuilder {
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum size of the results that is returned per call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of the results that is returned per call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum size of the results that is returned per call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The Amazon Resource Name (ARN) of the audience generation job that you are interested in.</p>
    pub fn audience_generation_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.audience_generation_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the audience generation job that you are interested in.</p>
    pub fn set_audience_generation_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.audience_generation_job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the audience generation job that you are interested in.</p>
    pub fn get_audience_generation_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.audience_generation_job_arn
    }
    /// Consumes the builder and constructs a [`ListAudienceExportJobsInput`](crate::operation::list_audience_export_jobs::ListAudienceExportJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_audience_export_jobs::ListAudienceExportJobsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_audience_export_jobs::ListAudienceExportJobsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            audience_generation_job_arn: self.audience_generation_job_arn,
        })
    }
}
