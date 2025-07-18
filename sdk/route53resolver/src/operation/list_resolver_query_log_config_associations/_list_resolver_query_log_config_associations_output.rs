// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResolverQueryLogConfigAssociationsOutput {
    /// <p>If there are more than <code>MaxResults</code> query logging associations, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The total number of query logging associations that were created by the current account in the specified Region. This count can differ from the number of associations that are returned in a <code>ListResolverQueryLogConfigAssociations</code> response, depending on the values that you specify in the request.</p>
    pub total_count: i32,
    /// <p>The total number of query logging associations that were created by the current account in the specified Region and that match the filters that were specified in the <code>ListResolverQueryLogConfigAssociations</code> request. For the total number of associations that were created by the current account in the specified Region, see <code>TotalCount</code>.</p>
    pub total_filtered_count: i32,
    /// <p>A list that contains one <code>ResolverQueryLogConfigAssociations</code> element for each query logging association that matches the values that you specified for <code>Filter</code>.</p>
    pub resolver_query_log_config_associations: ::std::option::Option<::std::vec::Vec<crate::types::ResolverQueryLogConfigAssociation>>,
    _request_id: Option<String>,
}
impl ListResolverQueryLogConfigAssociationsOutput {
    /// <p>If there are more than <code>MaxResults</code> query logging associations, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region. This count can differ from the number of associations that are returned in a <code>ListResolverQueryLogConfigAssociations</code> response, depending on the values that you specify in the request.</p>
    pub fn total_count(&self) -> i32 {
        self.total_count
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region and that match the filters that were specified in the <code>ListResolverQueryLogConfigAssociations</code> request. For the total number of associations that were created by the current account in the specified Region, see <code>TotalCount</code>.</p>
    pub fn total_filtered_count(&self) -> i32 {
        self.total_filtered_count
    }
    /// <p>A list that contains one <code>ResolverQueryLogConfigAssociations</code> element for each query logging association that matches the values that you specified for <code>Filter</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resolver_query_log_config_associations.is_none()`.
    pub fn resolver_query_log_config_associations(&self) -> &[crate::types::ResolverQueryLogConfigAssociation] {
        self.resolver_query_log_config_associations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListResolverQueryLogConfigAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListResolverQueryLogConfigAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`ListResolverQueryLogConfigAssociationsOutput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsOutput).
    pub fn builder() -> crate::operation::list_resolver_query_log_config_associations::builders::ListResolverQueryLogConfigAssociationsOutputBuilder {
        crate::operation::list_resolver_query_log_config_associations::builders::ListResolverQueryLogConfigAssociationsOutputBuilder::default()
    }
}

/// A builder for [`ListResolverQueryLogConfigAssociationsOutput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResolverQueryLogConfigAssociationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) total_count: ::std::option::Option<i32>,
    pub(crate) total_filtered_count: ::std::option::Option<i32>,
    pub(crate) resolver_query_log_config_associations: ::std::option::Option<::std::vec::Vec<crate::types::ResolverQueryLogConfigAssociation>>,
    _request_id: Option<String>,
}
impl ListResolverQueryLogConfigAssociationsOutputBuilder {
    /// <p>If there are more than <code>MaxResults</code> query logging associations, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more than <code>MaxResults</code> query logging associations, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more than <code>MaxResults</code> query logging associations, you can submit another <code>ListResolverQueryLogConfigAssociations</code> request to get the next group of associations. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region. This count can differ from the number of associations that are returned in a <code>ListResolverQueryLogConfigAssociations</code> response, depending on the values that you specify in the request.</p>
    pub fn total_count(mut self, input: i32) -> Self {
        self.total_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region. This count can differ from the number of associations that are returned in a <code>ListResolverQueryLogConfigAssociations</code> response, depending on the values that you specify in the request.</p>
    pub fn set_total_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_count = input;
        self
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region. This count can differ from the number of associations that are returned in a <code>ListResolverQueryLogConfigAssociations</code> response, depending on the values that you specify in the request.</p>
    pub fn get_total_count(&self) -> &::std::option::Option<i32> {
        &self.total_count
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region and that match the filters that were specified in the <code>ListResolverQueryLogConfigAssociations</code> request. For the total number of associations that were created by the current account in the specified Region, see <code>TotalCount</code>.</p>
    pub fn total_filtered_count(mut self, input: i32) -> Self {
        self.total_filtered_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region and that match the filters that were specified in the <code>ListResolverQueryLogConfigAssociations</code> request. For the total number of associations that were created by the current account in the specified Region, see <code>TotalCount</code>.</p>
    pub fn set_total_filtered_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_filtered_count = input;
        self
    }
    /// <p>The total number of query logging associations that were created by the current account in the specified Region and that match the filters that were specified in the <code>ListResolverQueryLogConfigAssociations</code> request. For the total number of associations that were created by the current account in the specified Region, see <code>TotalCount</code>.</p>
    pub fn get_total_filtered_count(&self) -> &::std::option::Option<i32> {
        &self.total_filtered_count
    }
    /// Appends an item to `resolver_query_log_config_associations`.
    ///
    /// To override the contents of this collection use [`set_resolver_query_log_config_associations`](Self::set_resolver_query_log_config_associations).
    ///
    /// <p>A list that contains one <code>ResolverQueryLogConfigAssociations</code> element for each query logging association that matches the values that you specified for <code>Filter</code>.</p>
    pub fn resolver_query_log_config_associations(mut self, input: crate::types::ResolverQueryLogConfigAssociation) -> Self {
        let mut v = self.resolver_query_log_config_associations.unwrap_or_default();
        v.push(input);
        self.resolver_query_log_config_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list that contains one <code>ResolverQueryLogConfigAssociations</code> element for each query logging association that matches the values that you specified for <code>Filter</code>.</p>
    pub fn set_resolver_query_log_config_associations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ResolverQueryLogConfigAssociation>>,
    ) -> Self {
        self.resolver_query_log_config_associations = input;
        self
    }
    /// <p>A list that contains one <code>ResolverQueryLogConfigAssociations</code> element for each query logging association that matches the values that you specified for <code>Filter</code>.</p>
    pub fn get_resolver_query_log_config_associations(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::ResolverQueryLogConfigAssociation>> {
        &self.resolver_query_log_config_associations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListResolverQueryLogConfigAssociationsOutput`](crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsOutput).
    pub fn build(self) -> crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsOutput {
        crate::operation::list_resolver_query_log_config_associations::ListResolverQueryLogConfigAssociationsOutput {
            next_token: self.next_token,
            total_count: self.total_count.unwrap_or_default(),
            total_filtered_count: self.total_filtered_count.unwrap_or_default(),
            resolver_query_log_config_associations: self.resolver_query_log_config_associations,
            _request_id: self._request_id,
        }
    }
}
