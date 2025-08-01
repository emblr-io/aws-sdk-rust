// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSubscriptionRequestsInput {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the status of the subscription requests.</p><note>
    /// <p>This is not a required parameter, but if not specified, by default, Amazon DataZone returns only <code>PENDING</code> subscription requests.</p>
    /// </note>
    pub status: ::std::option::Option<crate::types::SubscriptionRequestStatus>,
    /// <p>The identifier of the subscribed listing.</p>
    pub subscribed_listing_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the project for the subscription requests.</p>
    pub owning_project_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the subscription request approver's project.</p>
    pub approver_project_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the way to sort the results of this action.</p>
    pub sort_by: ::std::option::Option<crate::types::SortKey>,
    /// <p>Specifies the sort order for the results of this action.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>The maximum number of subscription requests to return in a single call to <code>ListSubscriptionRequests</code>. When the number of subscription requests to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>When the number of subscription requests is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of subscription requests, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListSubscriptionRequestsInput {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>Specifies the status of the subscription requests.</p><note>
    /// <p>This is not a required parameter, but if not specified, by default, Amazon DataZone returns only <code>PENDING</code> subscription requests.</p>
    /// </note>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SubscriptionRequestStatus> {
        self.status.as_ref()
    }
    /// <p>The identifier of the subscribed listing.</p>
    pub fn subscribed_listing_id(&self) -> ::std::option::Option<&str> {
        self.subscribed_listing_id.as_deref()
    }
    /// <p>The identifier of the project for the subscription requests.</p>
    pub fn owning_project_id(&self) -> ::std::option::Option<&str> {
        self.owning_project_id.as_deref()
    }
    /// <p>The identifier of the subscription request approver's project.</p>
    pub fn approver_project_id(&self) -> ::std::option::Option<&str> {
        self.approver_project_id.as_deref()
    }
    /// <p>Specifies the way to sort the results of this action.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::SortKey> {
        self.sort_by.as_ref()
    }
    /// <p>Specifies the sort order for the results of this action.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>The maximum number of subscription requests to return in a single call to <code>ListSubscriptionRequests</code>. When the number of subscription requests to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>When the number of subscription requests is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of subscription requests, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListSubscriptionRequestsInput {
    /// Creates a new builder-style object to manufacture [`ListSubscriptionRequestsInput`](crate::operation::list_subscription_requests::ListSubscriptionRequestsInput).
    pub fn builder() -> crate::operation::list_subscription_requests::builders::ListSubscriptionRequestsInputBuilder {
        crate::operation::list_subscription_requests::builders::ListSubscriptionRequestsInputBuilder::default()
    }
}

/// A builder for [`ListSubscriptionRequestsInput`](crate::operation::list_subscription_requests::ListSubscriptionRequestsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSubscriptionRequestsInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SubscriptionRequestStatus>,
    pub(crate) subscribed_listing_id: ::std::option::Option<::std::string::String>,
    pub(crate) owning_project_id: ::std::option::Option<::std::string::String>,
    pub(crate) approver_project_id: ::std::option::Option<::std::string::String>,
    pub(crate) sort_by: ::std::option::Option<crate::types::SortKey>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListSubscriptionRequestsInputBuilder {
    /// <p>The identifier of the Amazon DataZone domain.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>Specifies the status of the subscription requests.</p><note>
    /// <p>This is not a required parameter, but if not specified, by default, Amazon DataZone returns only <code>PENDING</code> subscription requests.</p>
    /// </note>
    pub fn status(mut self, input: crate::types::SubscriptionRequestStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the status of the subscription requests.</p><note>
    /// <p>This is not a required parameter, but if not specified, by default, Amazon DataZone returns only <code>PENDING</code> subscription requests.</p>
    /// </note>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SubscriptionRequestStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies the status of the subscription requests.</p><note>
    /// <p>This is not a required parameter, but if not specified, by default, Amazon DataZone returns only <code>PENDING</code> subscription requests.</p>
    /// </note>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SubscriptionRequestStatus> {
        &self.status
    }
    /// <p>The identifier of the subscribed listing.</p>
    pub fn subscribed_listing_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscribed_listing_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscribed listing.</p>
    pub fn set_subscribed_listing_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscribed_listing_id = input;
        self
    }
    /// <p>The identifier of the subscribed listing.</p>
    pub fn get_subscribed_listing_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscribed_listing_id
    }
    /// <p>The identifier of the project for the subscription requests.</p>
    pub fn owning_project_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owning_project_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the project for the subscription requests.</p>
    pub fn set_owning_project_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owning_project_id = input;
        self
    }
    /// <p>The identifier of the project for the subscription requests.</p>
    pub fn get_owning_project_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owning_project_id
    }
    /// <p>The identifier of the subscription request approver's project.</p>
    pub fn approver_project_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.approver_project_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription request approver's project.</p>
    pub fn set_approver_project_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.approver_project_id = input;
        self
    }
    /// <p>The identifier of the subscription request approver's project.</p>
    pub fn get_approver_project_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.approver_project_id
    }
    /// <p>Specifies the way to sort the results of this action.</p>
    pub fn sort_by(mut self, input: crate::types::SortKey) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the way to sort the results of this action.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::SortKey>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Specifies the way to sort the results of this action.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::SortKey> {
        &self.sort_by
    }
    /// <p>Specifies the sort order for the results of this action.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the sort order for the results of this action.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>Specifies the sort order for the results of this action.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>The maximum number of subscription requests to return in a single call to <code>ListSubscriptionRequests</code>. When the number of subscription requests to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of subscription requests to return in a single call to <code>ListSubscriptionRequests</code>. When the number of subscription requests to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of subscription requests to return in a single call to <code>ListSubscriptionRequests</code>. When the number of subscription requests to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>When the number of subscription requests is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of subscription requests, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of subscription requests is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of subscription requests, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of subscription requests is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of subscription requests, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListSubscriptionRequests</code> to list the next set of subscription requests.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListSubscriptionRequestsInput`](crate::operation::list_subscription_requests::ListSubscriptionRequestsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_subscription_requests::ListSubscriptionRequestsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_subscription_requests::ListSubscriptionRequestsInput {
            domain_identifier: self.domain_identifier,
            status: self.status,
            subscribed_listing_id: self.subscribed_listing_id,
            owning_project_id: self.owning_project_id,
            approver_project_id: self.approver_project_id,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
