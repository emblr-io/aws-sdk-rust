// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchPromptsInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return per page.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Filters to be applied to search results.</p>
    pub search_filter: ::std::option::Option<crate::types::PromptSearchFilter>,
    /// <p>The search criteria to be used to return prompts.</p>
    pub search_criteria: ::std::option::Option<crate::types::PromptSearchCriteria>,
}
impl SearchPromptsInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Filters to be applied to search results.</p>
    pub fn search_filter(&self) -> ::std::option::Option<&crate::types::PromptSearchFilter> {
        self.search_filter.as_ref()
    }
    /// <p>The search criteria to be used to return prompts.</p>
    pub fn search_criteria(&self) -> ::std::option::Option<&crate::types::PromptSearchCriteria> {
        self.search_criteria.as_ref()
    }
}
impl SearchPromptsInput {
    /// Creates a new builder-style object to manufacture [`SearchPromptsInput`](crate::operation::search_prompts::SearchPromptsInput).
    pub fn builder() -> crate::operation::search_prompts::builders::SearchPromptsInputBuilder {
        crate::operation::search_prompts::builders::SearchPromptsInputBuilder::default()
    }
}

/// A builder for [`SearchPromptsInput`](crate::operation::search_prompts::SearchPromptsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchPromptsInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) search_filter: ::std::option::Option<crate::types::PromptSearchFilter>,
    pub(crate) search_criteria: ::std::option::Option<crate::types::PromptSearchCriteria>,
}
impl SearchPromptsInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Filters to be applied to search results.</p>
    pub fn search_filter(mut self, input: crate::types::PromptSearchFilter) -> Self {
        self.search_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters to be applied to search results.</p>
    pub fn set_search_filter(mut self, input: ::std::option::Option<crate::types::PromptSearchFilter>) -> Self {
        self.search_filter = input;
        self
    }
    /// <p>Filters to be applied to search results.</p>
    pub fn get_search_filter(&self) -> &::std::option::Option<crate::types::PromptSearchFilter> {
        &self.search_filter
    }
    /// <p>The search criteria to be used to return prompts.</p>
    pub fn search_criteria(mut self, input: crate::types::PromptSearchCriteria) -> Self {
        self.search_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>The search criteria to be used to return prompts.</p>
    pub fn set_search_criteria(mut self, input: ::std::option::Option<crate::types::PromptSearchCriteria>) -> Self {
        self.search_criteria = input;
        self
    }
    /// <p>The search criteria to be used to return prompts.</p>
    pub fn get_search_criteria(&self) -> &::std::option::Option<crate::types::PromptSearchCriteria> {
        &self.search_criteria
    }
    /// Consumes the builder and constructs a [`SearchPromptsInput`](crate::operation::search_prompts::SearchPromptsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::search_prompts::SearchPromptsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_prompts::SearchPromptsInput {
            instance_id: self.instance_id,
            next_token: self.next_token,
            max_results: self.max_results,
            search_filter: self.search_filter,
            search_criteria: self.search_criteria,
        })
    }
}
