// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchInput {
    /// <p>The name of the SageMaker resource to search for.</p>
    pub resource: ::std::option::Option<crate::types::ResourceType>,
    /// <p>A Boolean conditional statement. Resources must satisfy this condition to be included in search results. You must provide at least one subexpression, filter, or nested filter. The maximum number of recursive <code>SubExpressions</code>, <code>NestedFilters</code>, and <code>Filters</code> that can be included in a <code>SearchExpression</code> object is 50.</p>
    pub search_expression: ::std::option::Option<crate::types::SearchExpression>,
    /// <p>The name of the resource property used to sort the <code>SearchResults</code>. The default is <code>LastModifiedTime</code>.</p>
    pub sort_by: ::std::option::Option<::std::string::String>,
    /// <p>How <code>SearchResults</code> are ordered. Valid values are <code>Ascending</code> or <code>Descending</code>. The default is <code>Descending</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SearchSortOrder>,
    /// <p>If more than <code>MaxResults</code> resources match the specified <code>SearchExpression</code>, the response includes a <code>NextToken</code>. The <code>NextToken</code> can be passed to the next <code>SearchRequest</code> to continue retrieving results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A cross account filter option. When the value is <code>"CrossAccount"</code> the search results will only include resources made discoverable to you from other accounts. When the value is <code>"SameAccount"</code> or <code>null</code> the search results will only include resources from your account. Default is <code>null</code>. For more information on searching for resources made discoverable to your account, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-cross-account-discoverability-use.html"> Search discoverable resources</a> in the SageMaker Developer Guide. The maximum number of <code>ResourceCatalog</code>s viewable is 1000.</p>
    pub cross_account_filter_option: ::std::option::Option<crate::types::CrossAccountFilterOption>,
    /// <p>Limits the results of your search request to the resources that you can access.</p>
    pub visibility_conditions: ::std::option::Option<::std::vec::Vec<crate::types::VisibilityConditions>>,
}
impl SearchInput {
    /// <p>The name of the SageMaker resource to search for.</p>
    pub fn resource(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource.as_ref()
    }
    /// <p>A Boolean conditional statement. Resources must satisfy this condition to be included in search results. You must provide at least one subexpression, filter, or nested filter. The maximum number of recursive <code>SubExpressions</code>, <code>NestedFilters</code>, and <code>Filters</code> that can be included in a <code>SearchExpression</code> object is 50.</p>
    pub fn search_expression(&self) -> ::std::option::Option<&crate::types::SearchExpression> {
        self.search_expression.as_ref()
    }
    /// <p>The name of the resource property used to sort the <code>SearchResults</code>. The default is <code>LastModifiedTime</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&str> {
        self.sort_by.as_deref()
    }
    /// <p>How <code>SearchResults</code> are ordered. Valid values are <code>Ascending</code> or <code>Descending</code>. The default is <code>Descending</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SearchSortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>If more than <code>MaxResults</code> resources match the specified <code>SearchExpression</code>, the response includes a <code>NextToken</code>. The <code>NextToken</code> can be passed to the next <code>SearchRequest</code> to continue retrieving results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A cross account filter option. When the value is <code>"CrossAccount"</code> the search results will only include resources made discoverable to you from other accounts. When the value is <code>"SameAccount"</code> or <code>null</code> the search results will only include resources from your account. Default is <code>null</code>. For more information on searching for resources made discoverable to your account, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-cross-account-discoverability-use.html"> Search discoverable resources</a> in the SageMaker Developer Guide. The maximum number of <code>ResourceCatalog</code>s viewable is 1000.</p>
    pub fn cross_account_filter_option(&self) -> ::std::option::Option<&crate::types::CrossAccountFilterOption> {
        self.cross_account_filter_option.as_ref()
    }
    /// <p>Limits the results of your search request to the resources that you can access.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.visibility_conditions.is_none()`.
    pub fn visibility_conditions(&self) -> &[crate::types::VisibilityConditions] {
        self.visibility_conditions.as_deref().unwrap_or_default()
    }
}
impl SearchInput {
    /// Creates a new builder-style object to manufacture [`SearchInput`](crate::operation::search::SearchInput).
    pub fn builder() -> crate::operation::search::builders::SearchInputBuilder {
        crate::operation::search::builders::SearchInputBuilder::default()
    }
}

/// A builder for [`SearchInput`](crate::operation::search::SearchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchInputBuilder {
    pub(crate) resource: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) search_expression: ::std::option::Option<crate::types::SearchExpression>,
    pub(crate) sort_by: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SearchSortOrder>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) cross_account_filter_option: ::std::option::Option<crate::types::CrossAccountFilterOption>,
    pub(crate) visibility_conditions: ::std::option::Option<::std::vec::Vec<crate::types::VisibilityConditions>>,
}
impl SearchInputBuilder {
    /// <p>The name of the SageMaker resource to search for.</p>
    /// This field is required.
    pub fn resource(mut self, input: crate::types::ResourceType) -> Self {
        self.resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the SageMaker resource to search for.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The name of the SageMaker resource to search for.</p>
    pub fn get_resource(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource
    }
    /// <p>A Boolean conditional statement. Resources must satisfy this condition to be included in search results. You must provide at least one subexpression, filter, or nested filter. The maximum number of recursive <code>SubExpressions</code>, <code>NestedFilters</code>, and <code>Filters</code> that can be included in a <code>SearchExpression</code> object is 50.</p>
    pub fn search_expression(mut self, input: crate::types::SearchExpression) -> Self {
        self.search_expression = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean conditional statement. Resources must satisfy this condition to be included in search results. You must provide at least one subexpression, filter, or nested filter. The maximum number of recursive <code>SubExpressions</code>, <code>NestedFilters</code>, and <code>Filters</code> that can be included in a <code>SearchExpression</code> object is 50.</p>
    pub fn set_search_expression(mut self, input: ::std::option::Option<crate::types::SearchExpression>) -> Self {
        self.search_expression = input;
        self
    }
    /// <p>A Boolean conditional statement. Resources must satisfy this condition to be included in search results. You must provide at least one subexpression, filter, or nested filter. The maximum number of recursive <code>SubExpressions</code>, <code>NestedFilters</code>, and <code>Filters</code> that can be included in a <code>SearchExpression</code> object is 50.</p>
    pub fn get_search_expression(&self) -> &::std::option::Option<crate::types::SearchExpression> {
        &self.search_expression
    }
    /// <p>The name of the resource property used to sort the <code>SearchResults</code>. The default is <code>LastModifiedTime</code>.</p>
    pub fn sort_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sort_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource property used to sort the <code>SearchResults</code>. The default is <code>LastModifiedTime</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The name of the resource property used to sort the <code>SearchResults</code>. The default is <code>LastModifiedTime</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.sort_by
    }
    /// <p>How <code>SearchResults</code> are ordered. Valid values are <code>Ascending</code> or <code>Descending</code>. The default is <code>Descending</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SearchSortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>How <code>SearchResults</code> are ordered. Valid values are <code>Ascending</code> or <code>Descending</code>. The default is <code>Descending</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SearchSortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>How <code>SearchResults</code> are ordered. Valid values are <code>Ascending</code> or <code>Descending</code>. The default is <code>Descending</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SearchSortOrder> {
        &self.sort_order
    }
    /// <p>If more than <code>MaxResults</code> resources match the specified <code>SearchExpression</code>, the response includes a <code>NextToken</code>. The <code>NextToken</code> can be passed to the next <code>SearchRequest</code> to continue retrieving results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If more than <code>MaxResults</code> resources match the specified <code>SearchExpression</code>, the response includes a <code>NextToken</code>. The <code>NextToken</code> can be passed to the next <code>SearchRequest</code> to continue retrieving results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If more than <code>MaxResults</code> resources match the specified <code>SearchExpression</code>, the response includes a <code>NextToken</code>. The <code>NextToken</code> can be passed to the next <code>SearchRequest</code> to continue retrieving results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A cross account filter option. When the value is <code>"CrossAccount"</code> the search results will only include resources made discoverable to you from other accounts. When the value is <code>"SameAccount"</code> or <code>null</code> the search results will only include resources from your account. Default is <code>null</code>. For more information on searching for resources made discoverable to your account, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-cross-account-discoverability-use.html"> Search discoverable resources</a> in the SageMaker Developer Guide. The maximum number of <code>ResourceCatalog</code>s viewable is 1000.</p>
    pub fn cross_account_filter_option(mut self, input: crate::types::CrossAccountFilterOption) -> Self {
        self.cross_account_filter_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>A cross account filter option. When the value is <code>"CrossAccount"</code> the search results will only include resources made discoverable to you from other accounts. When the value is <code>"SameAccount"</code> or <code>null</code> the search results will only include resources from your account. Default is <code>null</code>. For more information on searching for resources made discoverable to your account, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-cross-account-discoverability-use.html"> Search discoverable resources</a> in the SageMaker Developer Guide. The maximum number of <code>ResourceCatalog</code>s viewable is 1000.</p>
    pub fn set_cross_account_filter_option(mut self, input: ::std::option::Option<crate::types::CrossAccountFilterOption>) -> Self {
        self.cross_account_filter_option = input;
        self
    }
    /// <p>A cross account filter option. When the value is <code>"CrossAccount"</code> the search results will only include resources made discoverable to you from other accounts. When the value is <code>"SameAccount"</code> or <code>null</code> the search results will only include resources from your account. Default is <code>null</code>. For more information on searching for resources made discoverable to your account, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-cross-account-discoverability-use.html"> Search discoverable resources</a> in the SageMaker Developer Guide. The maximum number of <code>ResourceCatalog</code>s viewable is 1000.</p>
    pub fn get_cross_account_filter_option(&self) -> &::std::option::Option<crate::types::CrossAccountFilterOption> {
        &self.cross_account_filter_option
    }
    /// Appends an item to `visibility_conditions`.
    ///
    /// To override the contents of this collection use [`set_visibility_conditions`](Self::set_visibility_conditions).
    ///
    /// <p>Limits the results of your search request to the resources that you can access.</p>
    pub fn visibility_conditions(mut self, input: crate::types::VisibilityConditions) -> Self {
        let mut v = self.visibility_conditions.unwrap_or_default();
        v.push(input);
        self.visibility_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Limits the results of your search request to the resources that you can access.</p>
    pub fn set_visibility_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VisibilityConditions>>) -> Self {
        self.visibility_conditions = input;
        self
    }
    /// <p>Limits the results of your search request to the resources that you can access.</p>
    pub fn get_visibility_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VisibilityConditions>> {
        &self.visibility_conditions
    }
    /// Consumes the builder and constructs a [`SearchInput`](crate::operation::search::SearchInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::search::SearchInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search::SearchInput {
            resource: self.resource,
            search_expression: self.search_expression,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            next_token: self.next_token,
            max_results: self.max_results,
            cross_account_filter_option: self.cross_account_filter_option,
            visibility_conditions: self.visibility_conditions,
        })
    }
}
