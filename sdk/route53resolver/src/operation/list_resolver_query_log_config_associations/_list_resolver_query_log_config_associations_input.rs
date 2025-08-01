// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResolverQueryLogConfigAssociationsInput {
    /// <p>The maximum number of query logging associations that you want to return in the response to a <code>ListResolverQueryLogConfigAssociations</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging associations.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>For the first <code>ListResolverQueryLogConfigAssociations</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging associations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An optional specification to return a subset of query logging associations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The element that you want Resolver to sort query logging associations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>CreationTime</code>: The ID of the query logging association.</p></li>
    /// <li>
    /// <p><code>Error</code>: If the value of <code>Status</code> is <code>FAILED</code>, the value of <code>Error</code> indicates the cause:</p>
    /// <ul>
    /// <li>
    /// <p><code>DESTINATION_NOT_FOUND</code>: The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Permissions don't allow sending logs to the destination.</p></li>
    /// </ul>
    /// <p>If <code>Status</code> is a value other than <code>FAILED</code>, <code>ERROR</code> is null.</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the query logging association</p></li>
    /// <li>
    /// <p><code>ResolverQueryLogConfigId</code>: The ID of the query logging configuration</p></li>
    /// <li>
    /// <p><code>ResourceId</code>: The ID of the VPC that is associated with the query logging configuration</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating an association between an Amazon VPC and a query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The association between an Amazon VPC and a query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging association.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging association. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub sort_by: ::std::option::Option<::std::string::String>,
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging associations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListResolverQueryLogConfigAssociationsInput {
    /// <p>The maximum number of query logging associations that you want to return in the response to a <code>ListResolverQueryLogConfigAssociations</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging associations.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>For the first <code>ListResolverQueryLogConfigAssociations</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging associations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An optional specification to return a subset of query logging associations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The element that you want Resolver to sort query logging associations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>CreationTime</code>: The ID of the query logging association.</p></li>
    /// <li>
    /// <p><code>Error</code>: If the value of <code>Status</code> is <code>FAILED</code>, the value of <code>Error</code> indicates the cause:</p>
    /// <ul>
    /// <li>
    /// <p><code>DESTINATION_NOT_FOUND</code>: The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Permissions don't allow sending logs to the destination.</p></li>
    /// </ul>
    /// <p>If <code>Status</code> is a value other than <code>FAILED</code>, <code>ERROR</code> is null.</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the query logging association</p></li>
    /// <li>
    /// <p><code>ResolverQueryLogConfigId</code>: The ID of the query logging configuration</p></li>
    /// <li>
    /// <p><code>ResourceId</code>: The ID of the VPC that is associated with the query logging configuration</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating an association between an Amazon VPC and a query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The association between an Amazon VPC and a query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging association.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging association. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn sort_by(&self) -> ::std::option::Option<&str> {
        self.sort_by.as_deref()
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging associations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
}
impl ListResolverQueryLogConfigAssociationsInput {
    /// Creates a new builder-style object to manufacture [`ListResolverQueryLogConfigAssociationsInput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsInput).
    pub fn builder() -> crate::operation::list_resolver_query_log_config_associations::builders::ListResolverQueryLogConfigAssociationsInputBuilder {
        crate::operation::list_resolver_query_log_config_associations::builders::ListResolverQueryLogConfigAssociationsInputBuilder::default()
    }
}

/// A builder for [`ListResolverQueryLogConfigAssociationsInput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResolverQueryLogConfigAssociationsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) sort_by: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListResolverQueryLogConfigAssociationsInputBuilder {
    /// <p>The maximum number of query logging associations that you want to return in the response to a <code>ListResolverQueryLogConfigAssociations</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging associations.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of query logging associations that you want to return in the response to a <code>ListResolverQueryLogConfigAssociations</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging associations.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of query logging associations that you want to return in the response to a <code>ListResolverQueryLogConfigAssociations</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging associations.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>For the first <code>ListResolverQueryLogConfigAssociations</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging associations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For the first <code>ListResolverQueryLogConfigAssociations</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging associations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>For the first <code>ListResolverQueryLogConfigAssociations</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging associations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An optional specification to return a subset of query logging associations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An optional specification to return a subset of query logging associations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An optional specification to return a subset of query logging associations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The element that you want Resolver to sort query logging associations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>CreationTime</code>: The ID of the query logging association.</p></li>
    /// <li>
    /// <p><code>Error</code>: If the value of <code>Status</code> is <code>FAILED</code>, the value of <code>Error</code> indicates the cause:</p>
    /// <ul>
    /// <li>
    /// <p><code>DESTINATION_NOT_FOUND</code>: The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Permissions don't allow sending logs to the destination.</p></li>
    /// </ul>
    /// <p>If <code>Status</code> is a value other than <code>FAILED</code>, <code>ERROR</code> is null.</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the query logging association</p></li>
    /// <li>
    /// <p><code>ResolverQueryLogConfigId</code>: The ID of the query logging configuration</p></li>
    /// <li>
    /// <p><code>ResourceId</code>: The ID of the VPC that is associated with the query logging configuration</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating an association between an Amazon VPC and a query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The association between an Amazon VPC and a query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging association.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging association. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn sort_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sort_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The element that you want Resolver to sort query logging associations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>CreationTime</code>: The ID of the query logging association.</p></li>
    /// <li>
    /// <p><code>Error</code>: If the value of <code>Status</code> is <code>FAILED</code>, the value of <code>Error</code> indicates the cause:</p>
    /// <ul>
    /// <li>
    /// <p><code>DESTINATION_NOT_FOUND</code>: The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Permissions don't allow sending logs to the destination.</p></li>
    /// </ul>
    /// <p>If <code>Status</code> is a value other than <code>FAILED</code>, <code>ERROR</code> is null.</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the query logging association</p></li>
    /// <li>
    /// <p><code>ResolverQueryLogConfigId</code>: The ID of the query logging configuration</p></li>
    /// <li>
    /// <p><code>ResourceId</code>: The ID of the VPC that is associated with the query logging configuration</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating an association between an Amazon VPC and a query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The association between an Amazon VPC and a query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging association.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging association. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn set_sort_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The element that you want Resolver to sort query logging associations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>CreationTime</code>: The ID of the query logging association.</p></li>
    /// <li>
    /// <p><code>Error</code>: If the value of <code>Status</code> is <code>FAILED</code>, the value of <code>Error</code> indicates the cause:</p>
    /// <ul>
    /// <li>
    /// <p><code>DESTINATION_NOT_FOUND</code>: The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p><code>ACCESS_DENIED</code>: Permissions don't allow sending logs to the destination.</p></li>
    /// </ul>
    /// <p>If <code>Status</code> is a value other than <code>FAILED</code>, <code>ERROR</code> is null.</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the query logging association</p></li>
    /// <li>
    /// <p><code>ResolverQueryLogConfigId</code>: The ID of the query logging configuration</p></li>
    /// <li>
    /// <p><code>ResourceId</code>: The ID of the VPC that is associated with the query logging configuration</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating an association between an Amazon VPC and a query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The association between an Amazon VPC and a query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging association.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging association. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn get_sort_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.sort_by
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging associations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging associations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging associations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigAssociations</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// Consumes the builder and constructs a [`ListResolverQueryLogConfigAssociationsInput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsInput {
                max_results: self.max_results,
                next_token: self.next_token,
                filters: self.filters,
                sort_by: self.sort_by,
                sort_order: self.sort_order,
            },
        )
    }
}
