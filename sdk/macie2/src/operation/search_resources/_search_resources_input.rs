// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchResourcesInput {
    /// <p>The filter conditions that determine which S3 buckets to include or exclude from the query results.</p>
    pub bucket_criteria: ::std::option::Option<crate::types::SearchResourcesBucketCriteria>,
    /// <p>The maximum number of items to include in each page of the response. The default value is 50.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The criteria to use to sort the results.</p>
    pub sort_criteria: ::std::option::Option<crate::types::SearchResourcesSortCriteria>,
}
impl SearchResourcesInput {
    /// <p>The filter conditions that determine which S3 buckets to include or exclude from the query results.</p>
    pub fn bucket_criteria(&self) -> ::std::option::Option<&crate::types::SearchResourcesBucketCriteria> {
        self.bucket_criteria.as_ref()
    }
    /// <p>The maximum number of items to include in each page of the response. The default value is 50.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The criteria to use to sort the results.</p>
    pub fn sort_criteria(&self) -> ::std::option::Option<&crate::types::SearchResourcesSortCriteria> {
        self.sort_criteria.as_ref()
    }
}
impl SearchResourcesInput {
    /// Creates a new builder-style object to manufacture [`SearchResourcesInput`](crate::operation::search_resources::SearchResourcesInput).
    pub fn builder() -> crate::operation::search_resources::builders::SearchResourcesInputBuilder {
        crate::operation::search_resources::builders::SearchResourcesInputBuilder::default()
    }
}

/// A builder for [`SearchResourcesInput`](crate::operation::search_resources::SearchResourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchResourcesInputBuilder {
    pub(crate) bucket_criteria: ::std::option::Option<crate::types::SearchResourcesBucketCriteria>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) sort_criteria: ::std::option::Option<crate::types::SearchResourcesSortCriteria>,
}
impl SearchResourcesInputBuilder {
    /// <p>The filter conditions that determine which S3 buckets to include or exclude from the query results.</p>
    pub fn bucket_criteria(mut self, input: crate::types::SearchResourcesBucketCriteria) -> Self {
        self.bucket_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter conditions that determine which S3 buckets to include or exclude from the query results.</p>
    pub fn set_bucket_criteria(mut self, input: ::std::option::Option<crate::types::SearchResourcesBucketCriteria>) -> Self {
        self.bucket_criteria = input;
        self
    }
    /// <p>The filter conditions that determine which S3 buckets to include or exclude from the query results.</p>
    pub fn get_bucket_criteria(&self) -> &::std::option::Option<crate::types::SearchResourcesBucketCriteria> {
        &self.bucket_criteria
    }
    /// <p>The maximum number of items to include in each page of the response. The default value is 50.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to include in each page of the response. The default value is 50.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to include in each page of the response. The default value is 50.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The nextToken string that specifies which page of results to return in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The criteria to use to sort the results.</p>
    pub fn sort_criteria(mut self, input: crate::types::SearchResourcesSortCriteria) -> Self {
        self.sort_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>The criteria to use to sort the results.</p>
    pub fn set_sort_criteria(mut self, input: ::std::option::Option<crate::types::SearchResourcesSortCriteria>) -> Self {
        self.sort_criteria = input;
        self
    }
    /// <p>The criteria to use to sort the results.</p>
    pub fn get_sort_criteria(&self) -> &::std::option::Option<crate::types::SearchResourcesSortCriteria> {
        &self.sort_criteria
    }
    /// Consumes the builder and constructs a [`SearchResourcesInput`](crate::operation::search_resources::SearchResourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_resources::SearchResourcesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_resources::SearchResourcesInput {
            bucket_criteria: self.bucket_criteria,
            max_results: self.max_results,
            next_token: self.next_token,
            sort_criteria: self.sort_criteria,
        })
    }
}
