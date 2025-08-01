// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceSnapshotJobsInput {
    /// <p>Specifies the catalog related to the request.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call. If omitted, defaults to 50.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the engagement to filter the response.</p>
    pub engagement_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The status of the jobs to filter the response.</p>
    pub status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
    /// <p>Configures the sorting of the response. If omitted, results are sorted by <code>CreatedDate</code> in descending order.</p>
    pub sort: ::std::option::Option<crate::types::SortObject>,
}
impl ListResourceSnapshotJobsInput {
    /// <p>Specifies the catalog related to the request.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>The maximum number of results to return in a single call. If omitted, defaults to 50.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The identifier of the engagement to filter the response.</p>
    pub fn engagement_identifier(&self) -> ::std::option::Option<&str> {
        self.engagement_identifier.as_deref()
    }
    /// <p>The status of the jobs to filter the response.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ResourceSnapshotJobStatus> {
        self.status.as_ref()
    }
    /// <p>Configures the sorting of the response. If omitted, results are sorted by <code>CreatedDate</code> in descending order.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::SortObject> {
        self.sort.as_ref()
    }
}
impl ListResourceSnapshotJobsInput {
    /// Creates a new builder-style object to manufacture [`ListResourceSnapshotJobsInput`](crate::operation::list_resource_snapshot_jobs::ListResourceSnapshotJobsInput).
    pub fn builder() -> crate::operation::list_resource_snapshot_jobs::builders::ListResourceSnapshotJobsInputBuilder {
        crate::operation::list_resource_snapshot_jobs::builders::ListResourceSnapshotJobsInputBuilder::default()
    }
}

/// A builder for [`ListResourceSnapshotJobsInput`](crate::operation::list_resource_snapshot_jobs::ListResourceSnapshotJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceSnapshotJobsInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) engagement_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>,
    pub(crate) sort: ::std::option::Option<crate::types::SortObject>,
}
impl ListResourceSnapshotJobsInputBuilder {
    /// <p>Specifies the catalog related to the request.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog related to the request.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog related to the request.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>The maximum number of results to return in a single call. If omitted, defaults to 50.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call. If omitted, defaults to 50.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call. If omitted, defaults to 50.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The identifier of the engagement to filter the response.</p>
    pub fn engagement_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engagement_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the engagement to filter the response.</p>
    pub fn set_engagement_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engagement_identifier = input;
        self
    }
    /// <p>The identifier of the engagement to filter the response.</p>
    pub fn get_engagement_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.engagement_identifier
    }
    /// <p>The status of the jobs to filter the response.</p>
    pub fn status(mut self, input: crate::types::ResourceSnapshotJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the jobs to filter the response.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ResourceSnapshotJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the jobs to filter the response.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ResourceSnapshotJobStatus> {
        &self.status
    }
    /// <p>Configures the sorting of the response. If omitted, results are sorted by <code>CreatedDate</code> in descending order.</p>
    pub fn sort(mut self, input: crate::types::SortObject) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configures the sorting of the response. If omitted, results are sorted by <code>CreatedDate</code> in descending order.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::SortObject>) -> Self {
        self.sort = input;
        self
    }
    /// <p>Configures the sorting of the response. If omitted, results are sorted by <code>CreatedDate</code> in descending order.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::SortObject> {
        &self.sort
    }
    /// Consumes the builder and constructs a [`ListResourceSnapshotJobsInput`](crate::operation::list_resource_snapshot_jobs::ListResourceSnapshotJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resource_snapshot_jobs::ListResourceSnapshotJobsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_resource_snapshot_jobs::ListResourceSnapshotJobsInput {
            catalog: self.catalog,
            max_results: self.max_results,
            next_token: self.next_token,
            engagement_identifier: self.engagement_identifier,
            status: self.status,
            sort: self.sort,
        })
    }
}
