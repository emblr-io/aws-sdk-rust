// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request of DescribeSubscribersForNotification</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSubscribersForNotificationInput {
    /// <p>The <code>accountId</code> that is associated with the budget whose subscribers you want descriptions of.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the budget whose subscribers you want descriptions of.</p>
    pub budget_name: ::std::option::Option<::std::string::String>,
    /// <p>The notification whose subscribers you want to list.</p>
    pub notification: ::std::option::Option<crate::types::Notification>,
    /// <p>An optional integer that represents how many entries a paginated response contains.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token that you include in your request to indicate the next set of results that you want to retrieve.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeSubscribersForNotificationInput {
    /// <p>The <code>accountId</code> that is associated with the budget whose subscribers you want descriptions of.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The name of the budget whose subscribers you want descriptions of.</p>
    pub fn budget_name(&self) -> ::std::option::Option<&str> {
        self.budget_name.as_deref()
    }
    /// <p>The notification whose subscribers you want to list.</p>
    pub fn notification(&self) -> ::std::option::Option<&crate::types::Notification> {
        self.notification.as_ref()
    }
    /// <p>An optional integer that represents how many entries a paginated response contains.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token that you include in your request to indicate the next set of results that you want to retrieve.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeSubscribersForNotificationInput {
    /// Creates a new builder-style object to manufacture [`DescribeSubscribersForNotificationInput`](crate::operation::describe_subscribers_for_notification::DescribeSubscribersForNotificationInput).
    pub fn builder() -> crate::operation::describe_subscribers_for_notification::builders::DescribeSubscribersForNotificationInputBuilder {
        crate::operation::describe_subscribers_for_notification::builders::DescribeSubscribersForNotificationInputBuilder::default()
    }
}

/// A builder for [`DescribeSubscribersForNotificationInput`](crate::operation::describe_subscribers_for_notification::DescribeSubscribersForNotificationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSubscribersForNotificationInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) budget_name: ::std::option::Option<::std::string::String>,
    pub(crate) notification: ::std::option::Option<crate::types::Notification>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeSubscribersForNotificationInputBuilder {
    /// <p>The <code>accountId</code> that is associated with the budget whose subscribers you want descriptions of.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>accountId</code> that is associated with the budget whose subscribers you want descriptions of.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The <code>accountId</code> that is associated with the budget whose subscribers you want descriptions of.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The name of the budget whose subscribers you want descriptions of.</p>
    /// This field is required.
    pub fn budget_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.budget_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the budget whose subscribers you want descriptions of.</p>
    pub fn set_budget_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.budget_name = input;
        self
    }
    /// <p>The name of the budget whose subscribers you want descriptions of.</p>
    pub fn get_budget_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.budget_name
    }
    /// <p>The notification whose subscribers you want to list.</p>
    /// This field is required.
    pub fn notification(mut self, input: crate::types::Notification) -> Self {
        self.notification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The notification whose subscribers you want to list.</p>
    pub fn set_notification(mut self, input: ::std::option::Option<crate::types::Notification>) -> Self {
        self.notification = input;
        self
    }
    /// <p>The notification whose subscribers you want to list.</p>
    pub fn get_notification(&self) -> &::std::option::Option<crate::types::Notification> {
        &self.notification
    }
    /// <p>An optional integer that represents how many entries a paginated response contains.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional integer that represents how many entries a paginated response contains.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>An optional integer that represents how many entries a paginated response contains.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token that you include in your request to indicate the next set of results that you want to retrieve.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that you include in your request to indicate the next set of results that you want to retrieve.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that you include in your request to indicate the next set of results that you want to retrieve.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeSubscribersForNotificationInput`](crate::operation::describe_subscribers_for_notification::DescribeSubscribersForNotificationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_subscribers_for_notification::DescribeSubscribersForNotificationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_subscribers_for_notification::DescribeSubscribersForNotificationInput {
                account_id: self.account_id,
                budget_name: self.budget_name,
                notification: self.notification,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
