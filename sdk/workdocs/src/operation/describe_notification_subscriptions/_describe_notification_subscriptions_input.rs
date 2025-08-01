// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeNotificationSubscriptionsInput {
    /// <p>The ID of the organization.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return with this call.</p>
    pub limit: ::std::option::Option<i32>,
}
impl DescribeNotificationSubscriptionsInput {
    /// <p>The ID of the organization.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl DescribeNotificationSubscriptionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeNotificationSubscriptionsInput`](crate::operation::describe_notification_subscriptions::DescribeNotificationSubscriptionsInput).
    pub fn builder() -> crate::operation::describe_notification_subscriptions::builders::DescribeNotificationSubscriptionsInputBuilder {
        crate::operation::describe_notification_subscriptions::builders::DescribeNotificationSubscriptionsInputBuilder::default()
    }
}

/// A builder for [`DescribeNotificationSubscriptionsInput`](crate::operation::describe_notification_subscriptions::DescribeNotificationSubscriptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeNotificationSubscriptionsInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl DescribeNotificationSubscriptionsInputBuilder {
    /// <p>The ID of the organization.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the organization.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The ID of the organization.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`DescribeNotificationSubscriptionsInput`](crate::operation::describe_notification_subscriptions::DescribeNotificationSubscriptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_notification_subscriptions::DescribeNotificationSubscriptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_notification_subscriptions::DescribeNotificationSubscriptionsInput {
                organization_id: self.organization_id,
                marker: self.marker,
                limit: self.limit,
            },
        )
    }
}
