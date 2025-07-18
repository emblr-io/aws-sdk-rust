// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCreatedArtifactsInput {
    /// <p>The name of the ProgressUpdateStream.</p>
    pub progress_update_stream: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub migration_task_name: ::std::option::Option<::std::string::String>,
    /// <p>If a <code>NextToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>NextToken</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of results to be returned per page.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListCreatedArtifactsInput {
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn progress_update_stream(&self) -> ::std::option::Option<&str> {
        self.progress_update_stream.as_deref()
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn migration_task_name(&self) -> ::std::option::Option<&str> {
        self.migration_task_name.as_deref()
    }
    /// <p>If a <code>NextToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>NextToken</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of results to be returned per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListCreatedArtifactsInput {
    /// Creates a new builder-style object to manufacture [`ListCreatedArtifactsInput`](crate::operation::list_created_artifacts::ListCreatedArtifactsInput).
    pub fn builder() -> crate::operation::list_created_artifacts::builders::ListCreatedArtifactsInputBuilder {
        crate::operation::list_created_artifacts::builders::ListCreatedArtifactsInputBuilder::default()
    }
}

/// A builder for [`ListCreatedArtifactsInput`](crate::operation::list_created_artifacts::ListCreatedArtifactsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCreatedArtifactsInputBuilder {
    pub(crate) progress_update_stream: ::std::option::Option<::std::string::String>,
    pub(crate) migration_task_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListCreatedArtifactsInputBuilder {
    /// <p>The name of the ProgressUpdateStream.</p>
    /// This field is required.
    pub fn progress_update_stream(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.progress_update_stream = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn set_progress_update_stream(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.progress_update_stream = input;
        self
    }
    /// <p>The name of the ProgressUpdateStream.</p>
    pub fn get_progress_update_stream(&self) -> &::std::option::Option<::std::string::String> {
        &self.progress_update_stream
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    /// This field is required.
    pub fn migration_task_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.migration_task_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn set_migration_task_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.migration_task_name = input;
        self
    }
    /// <p>Unique identifier that references the migration task. <i>Do not store personal data in this field.</i></p>
    pub fn get_migration_task_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.migration_task_name
    }
    /// <p>If a <code>NextToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>NextToken</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If a <code>NextToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>NextToken</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If a <code>NextToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>NextToken</code>.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of results to be returned per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of results to be returned per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of results to be returned per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListCreatedArtifactsInput`](crate::operation::list_created_artifacts::ListCreatedArtifactsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_created_artifacts::ListCreatedArtifactsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_created_artifacts::ListCreatedArtifactsInput {
            progress_update_stream: self.progress_update_stream,
            migration_task_name: self.migration_task_name,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
