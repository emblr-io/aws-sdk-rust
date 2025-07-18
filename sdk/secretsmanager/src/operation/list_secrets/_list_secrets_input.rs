// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSecretsInput {
    /// <p>Specifies whether to include secrets scheduled for deletion. By default, secrets scheduled for deletion aren't included.</p>
    pub include_planned_deletion: ::std::option::Option<bool>,
    /// <p>The number of results to include in the response.</p>
    /// <p>If there are more results available, in the response, Secrets Manager includes <code>NextToken</code>. To get the next results, call <code>ListSecrets</code> again with the value from <code>NextToken</code>.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token that indicates where the output should continue from, if a previous call did not show all results. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The filters to apply to the list of secrets.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>Secrets are listed by <code>CreatedDate</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrderType>,
}
impl ListSecretsInput {
    /// <p>Specifies whether to include secrets scheduled for deletion. By default, secrets scheduled for deletion aren't included.</p>
    pub fn include_planned_deletion(&self) -> ::std::option::Option<bool> {
        self.include_planned_deletion
    }
    /// <p>The number of results to include in the response.</p>
    /// <p>If there are more results available, in the response, Secrets Manager includes <code>NextToken</code>. To get the next results, call <code>ListSecrets</code> again with the value from <code>NextToken</code>.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token that indicates where the output should continue from, if a previous call did not show all results. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The filters to apply to the list of secrets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Secrets are listed by <code>CreatedDate</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrderType> {
        self.sort_order.as_ref()
    }
}
impl ListSecretsInput {
    /// Creates a new builder-style object to manufacture [`ListSecretsInput`](crate::operation::list_secrets::ListSecretsInput).
    pub fn builder() -> crate::operation::list_secrets::builders::ListSecretsInputBuilder {
        crate::operation::list_secrets::builders::ListSecretsInputBuilder::default()
    }
}

/// A builder for [`ListSecretsInput`](crate::operation::list_secrets::ListSecretsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSecretsInputBuilder {
    pub(crate) include_planned_deletion: ::std::option::Option<bool>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrderType>,
}
impl ListSecretsInputBuilder {
    /// <p>Specifies whether to include secrets scheduled for deletion. By default, secrets scheduled for deletion aren't included.</p>
    pub fn include_planned_deletion(mut self, input: bool) -> Self {
        self.include_planned_deletion = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to include secrets scheduled for deletion. By default, secrets scheduled for deletion aren't included.</p>
    pub fn set_include_planned_deletion(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_planned_deletion = input;
        self
    }
    /// <p>Specifies whether to include secrets scheduled for deletion. By default, secrets scheduled for deletion aren't included.</p>
    pub fn get_include_planned_deletion(&self) -> &::std::option::Option<bool> {
        &self.include_planned_deletion
    }
    /// <p>The number of results to include in the response.</p>
    /// <p>If there are more results available, in the response, Secrets Manager includes <code>NextToken</code>. To get the next results, call <code>ListSecrets</code> again with the value from <code>NextToken</code>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of results to include in the response.</p>
    /// <p>If there are more results available, in the response, Secrets Manager includes <code>NextToken</code>. To get the next results, call <code>ListSecrets</code> again with the value from <code>NextToken</code>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of results to include in the response.</p>
    /// <p>If there are more results available, in the response, Secrets Manager includes <code>NextToken</code>. To get the next results, call <code>ListSecrets</code> again with the value from <code>NextToken</code>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token that indicates where the output should continue from, if a previous call did not show all results. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates where the output should continue from, if a previous call did not show all results. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates where the output should continue from, if a previous call did not show all results. To get the next results, call <code>ListSecrets</code> again with this value.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>The filters to apply to the list of secrets.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filters to apply to the list of secrets.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The filters to apply to the list of secrets.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>Secrets are listed by <code>CreatedDate</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrderType) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Secrets are listed by <code>CreatedDate</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrderType>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>Secrets are listed by <code>CreatedDate</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrderType> {
        &self.sort_order
    }
    /// Consumes the builder and constructs a [`ListSecretsInput`](crate::operation::list_secrets::ListSecretsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_secrets::ListSecretsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_secrets::ListSecretsInput {
            include_planned_deletion: self.include_planned_deletion,
            max_results: self.max_results,
            next_token: self.next_token,
            filters: self.filters,
            sort_order: self.sort_order,
        })
    }
}
