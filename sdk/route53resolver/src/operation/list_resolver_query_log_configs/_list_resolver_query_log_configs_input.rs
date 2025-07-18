// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResolverQueryLogConfigsInput {
    /// <p>The maximum number of query logging configurations that you want to return in the response to a <code>ListResolverQueryLogConfigs</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging configurations.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>For the first <code>ListResolverQueryLogConfigs</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging configurations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigs</code> request to get the next group of configurations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An optional specification to return a subset of query logging configurations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The element that you want Resolver to sort query logging configurations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>Arn</code>: The ARN of the query logging configuration</p></li>
    /// <li>
    /// <p><code>AssociationCount</code>: The number of VPCs that are associated with the specified configuration</p></li>
    /// <li>
    /// <p><code>CreationTime</code>: The date and time that Resolver returned when the configuration was created</p></li>
    /// <li>
    /// <p><code>CreatorRequestId</code>: The value that was specified for <code>CreatorRequestId</code> when the configuration was created</p></li>
    /// <li>
    /// <p><code>DestinationArn</code>: The location that logs are sent to</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the configuration</p></li>
    /// <li>
    /// <p><code>Name</code>: The name of the configuration</p></li>
    /// <li>
    /// <p><code>OwnerId</code>: The Amazon Web Services account number of the account that created the configuration</p></li>
    /// <li>
    /// <p><code>ShareStatus</code>: Whether the configuration is shared with other Amazon Web Services accounts or shared with the current account by another Amazon Web Services account. Sharing is configured through Resource Access Manager (RAM).</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating the query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging configuration.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging configuration. Here are two common causes:</p>
    /// <ul>
    /// <li>
    /// <p>The specified destination (for example, an Amazon S3 bucket) was deleted.</p></li>
    /// <li>
    /// <p>Permissions don't allow sending logs to the destination.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub sort_by: ::std::option::Option<::std::string::String>,
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging configurations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListResolverQueryLogConfigsInput {
    /// <p>The maximum number of query logging configurations that you want to return in the response to a <code>ListResolverQueryLogConfigs</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging configurations.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>For the first <code>ListResolverQueryLogConfigs</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging configurations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigs</code> request to get the next group of configurations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An optional specification to return a subset of query logging configurations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The element that you want Resolver to sort query logging configurations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>Arn</code>: The ARN of the query logging configuration</p></li>
    /// <li>
    /// <p><code>AssociationCount</code>: The number of VPCs that are associated with the specified configuration</p></li>
    /// <li>
    /// <p><code>CreationTime</code>: The date and time that Resolver returned when the configuration was created</p></li>
    /// <li>
    /// <p><code>CreatorRequestId</code>: The value that was specified for <code>CreatorRequestId</code> when the configuration was created</p></li>
    /// <li>
    /// <p><code>DestinationArn</code>: The location that logs are sent to</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the configuration</p></li>
    /// <li>
    /// <p><code>Name</code>: The name of the configuration</p></li>
    /// <li>
    /// <p><code>OwnerId</code>: The Amazon Web Services account number of the account that created the configuration</p></li>
    /// <li>
    /// <p><code>ShareStatus</code>: Whether the configuration is shared with other Amazon Web Services accounts or shared with the current account by another Amazon Web Services account. Sharing is configured through Resource Access Manager (RAM).</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating the query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging configuration.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging configuration. Here are two common causes:</p>
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
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging configurations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
}
impl ListResolverQueryLogConfigsInput {
    /// Creates a new builder-style object to manufacture [`ListResolverQueryLogConfigsInput`](crate::operation::list_resolver_query_log_configs::ListResolverQueryLogConfigsInput).
    pub fn builder() -> crate::operation::list_resolver_query_log_configs::builders::ListResolverQueryLogConfigsInputBuilder {
        crate::operation::list_resolver_query_log_configs::builders::ListResolverQueryLogConfigsInputBuilder::default()
    }
}

/// A builder for [`ListResolverQueryLogConfigsInput`](crate::operation::list_resolver_query_log_configs::ListResolverQueryLogConfigsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResolverQueryLogConfigsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) sort_by: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListResolverQueryLogConfigsInputBuilder {
    /// <p>The maximum number of query logging configurations that you want to return in the response to a <code>ListResolverQueryLogConfigs</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging configurations.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of query logging configurations that you want to return in the response to a <code>ListResolverQueryLogConfigs</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging configurations.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of query logging configurations that you want to return in the response to a <code>ListResolverQueryLogConfigs</code> request. If you don't specify a value for <code>MaxResults</code>, Resolver returns up to 100 query logging configurations.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>For the first <code>ListResolverQueryLogConfigs</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging configurations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigs</code> request to get the next group of configurations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For the first <code>ListResolverQueryLogConfigs</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging configurations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigs</code> request to get the next group of configurations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>For the first <code>ListResolverQueryLogConfigs</code> request, omit this value.</p>
    /// <p>If there are more than <code>MaxResults</code> query logging configurations that match the values that you specify for <code>Filters</code>, you can submit another <code>ListResolverQueryLogConfigs</code> request to get the next group of configurations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An optional specification to return a subset of query logging configurations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An optional specification to return a subset of query logging configurations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An optional specification to return a subset of query logging configurations.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same values for <code>Filters</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The element that you want Resolver to sort query logging configurations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>Arn</code>: The ARN of the query logging configuration</p></li>
    /// <li>
    /// <p><code>AssociationCount</code>: The number of VPCs that are associated with the specified configuration</p></li>
    /// <li>
    /// <p><code>CreationTime</code>: The date and time that Resolver returned when the configuration was created</p></li>
    /// <li>
    /// <p><code>CreatorRequestId</code>: The value that was specified for <code>CreatorRequestId</code> when the configuration was created</p></li>
    /// <li>
    /// <p><code>DestinationArn</code>: The location that logs are sent to</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the configuration</p></li>
    /// <li>
    /// <p><code>Name</code>: The name of the configuration</p></li>
    /// <li>
    /// <p><code>OwnerId</code>: The Amazon Web Services account number of the account that created the configuration</p></li>
    /// <li>
    /// <p><code>ShareStatus</code>: Whether the configuration is shared with other Amazon Web Services accounts or shared with the current account by another Amazon Web Services account. Sharing is configured through Resource Access Manager (RAM).</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating the query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging configuration.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging configuration. Here are two common causes:</p>
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
    /// <p>The element that you want Resolver to sort query logging configurations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>Arn</code>: The ARN of the query logging configuration</p></li>
    /// <li>
    /// <p><code>AssociationCount</code>: The number of VPCs that are associated with the specified configuration</p></li>
    /// <li>
    /// <p><code>CreationTime</code>: The date and time that Resolver returned when the configuration was created</p></li>
    /// <li>
    /// <p><code>CreatorRequestId</code>: The value that was specified for <code>CreatorRequestId</code> when the configuration was created</p></li>
    /// <li>
    /// <p><code>DestinationArn</code>: The location that logs are sent to</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the configuration</p></li>
    /// <li>
    /// <p><code>Name</code>: The name of the configuration</p></li>
    /// <li>
    /// <p><code>OwnerId</code>: The Amazon Web Services account number of the account that created the configuration</p></li>
    /// <li>
    /// <p><code>ShareStatus</code>: Whether the configuration is shared with other Amazon Web Services accounts or shared with the current account by another Amazon Web Services account. Sharing is configured through Resource Access Manager (RAM).</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating the query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging configuration.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging configuration. Here are two common causes:</p>
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
    /// <p>The element that you want Resolver to sort query logging configurations by.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortBy</code>, if any, as in the previous request.</p>
    /// </note>
    /// <p>Valid values include the following elements:</p>
    /// <ul>
    /// <li>
    /// <p><code>Arn</code>: The ARN of the query logging configuration</p></li>
    /// <li>
    /// <p><code>AssociationCount</code>: The number of VPCs that are associated with the specified configuration</p></li>
    /// <li>
    /// <p><code>CreationTime</code>: The date and time that Resolver returned when the configuration was created</p></li>
    /// <li>
    /// <p><code>CreatorRequestId</code>: The value that was specified for <code>CreatorRequestId</code> when the configuration was created</p></li>
    /// <li>
    /// <p><code>DestinationArn</code>: The location that logs are sent to</p></li>
    /// <li>
    /// <p><code>Id</code>: The ID of the configuration</p></li>
    /// <li>
    /// <p><code>Name</code>: The name of the configuration</p></li>
    /// <li>
    /// <p><code>OwnerId</code>: The Amazon Web Services account number of the account that created the configuration</p></li>
    /// <li>
    /// <p><code>ShareStatus</code>: Whether the configuration is shared with other Amazon Web Services accounts or shared with the current account by another Amazon Web Services account. Sharing is configured through Resource Access Manager (RAM).</p></li>
    /// <li>
    /// <p><code>Status</code>: The current status of the configuration. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code>: Resolver is creating the query logging configuration.</p></li>
    /// <li>
    /// <p><code>CREATED</code>: The query logging configuration was successfully created. Resolver is logging queries that originate in the specified VPC.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Resolver is deleting this query logging configuration.</p></li>
    /// <li>
    /// <p><code>FAILED</code>: Resolver either couldn't create or couldn't delete the query logging configuration. Here are two common causes:</p>
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
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging configurations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging configurations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>If you specified a value for <code>SortBy</code>, the order that you want query logging configurations to be listed in, <code>ASCENDING</code> or <code>DESCENDING</code>.</p><note>
    /// <p>If you submit a second or subsequent <code>ListResolverQueryLogConfigs</code> request and specify the <code>NextToken</code> parameter, you must use the same value for <code>SortOrder</code>, if any, as in the previous request.</p>
    /// </note>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// Consumes the builder and constructs a [`ListResolverQueryLogConfigsInput`](crate::operation::list_resolver_query_log_configs::ListResolverQueryLogConfigsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resolver_query_log_configs::ListResolverQueryLogConfigsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_resolver_query_log_configs::ListResolverQueryLogConfigsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            filters: self.filters,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
        })
    }
}
