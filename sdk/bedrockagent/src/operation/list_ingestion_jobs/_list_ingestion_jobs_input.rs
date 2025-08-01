// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIngestionJobsInput {
    /// <p>The unique identifier of the knowledge base for the list of data ingestion jobs.</p>
    pub knowledge_base_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the data source for the list of data ingestion jobs.</p>
    pub data_source_id: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the filters for filtering the data.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::IngestionJobFilter>>,
    /// <p>Contains details about how to sort the data.</p>
    pub sort_by: ::std::option::Option<crate::types::IngestionJobSortBy>,
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListIngestionJobsInput {
    /// <p>The unique identifier of the knowledge base for the list of data ingestion jobs.</p>
    pub fn knowledge_base_id(&self) -> ::std::option::Option<&str> {
        self.knowledge_base_id.as_deref()
    }
    /// <p>The unique identifier of the data source for the list of data ingestion jobs.</p>
    pub fn data_source_id(&self) -> ::std::option::Option<&str> {
        self.data_source_id.as_deref()
    }
    /// <p>Contains information about the filters for filtering the data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::IngestionJobFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Contains details about how to sort the data.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::IngestionJobSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListIngestionJobsInput {
    /// Creates a new builder-style object to manufacture [`ListIngestionJobsInput`](crate::operation::list_ingestion_jobs::ListIngestionJobsInput).
    pub fn builder() -> crate::operation::list_ingestion_jobs::builders::ListIngestionJobsInputBuilder {
        crate::operation::list_ingestion_jobs::builders::ListIngestionJobsInputBuilder::default()
    }
}

/// A builder for [`ListIngestionJobsInput`](crate::operation::list_ingestion_jobs::ListIngestionJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIngestionJobsInputBuilder {
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::IngestionJobFilter>>,
    pub(crate) sort_by: ::std::option::Option<crate::types::IngestionJobSortBy>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListIngestionJobsInputBuilder {
    /// <p>The unique identifier of the knowledge base for the list of data ingestion jobs.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the knowledge base for the list of data ingestion jobs.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The unique identifier of the knowledge base for the list of data ingestion jobs.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The unique identifier of the data source for the list of data ingestion jobs.</p>
    /// This field is required.
    pub fn data_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the data source for the list of data ingestion jobs.</p>
    pub fn set_data_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_id = input;
        self
    }
    /// <p>The unique identifier of the data source for the list of data ingestion jobs.</p>
    pub fn get_data_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_id
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Contains information about the filters for filtering the data.</p>
    pub fn filters(mut self, input: crate::types::IngestionJobFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information about the filters for filtering the data.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IngestionJobFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Contains information about the filters for filtering the data.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IngestionJobFilter>> {
        &self.filters
    }
    /// <p>Contains details about how to sort the data.</p>
    pub fn sort_by(mut self, input: crate::types::IngestionJobSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about how to sort the data.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::IngestionJobSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Contains details about how to sort the data.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::IngestionJobSortBy> {
        &self.sort_by
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response. If the total number of results is greater than this value, use the token returned in the response in the <code>nextToken</code> field when making another request to return the next batch of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the total number of results is greater than the <code>maxResults</code> value provided in the request, enter the token returned in the <code>nextToken</code> field in the response in this field to return the next batch of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListIngestionJobsInput`](crate::operation::list_ingestion_jobs::ListIngestionJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_ingestion_jobs::ListIngestionJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_ingestion_jobs::ListIngestionJobsInput {
            knowledge_base_id: self.knowledge_base_id,
            data_source_id: self.data_source_id,
            filters: self.filters,
            sort_by: self.sort_by,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
