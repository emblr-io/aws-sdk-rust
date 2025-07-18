// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstanceEventNotificationAttributesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DescribeInstanceEventNotificationAttributesInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DescribeInstanceEventNotificationAttributesInput {
    /// Creates a new builder-style object to manufacture [`DescribeInstanceEventNotificationAttributesInput`](crate::operation::describe_instance_event_notification_attributes::DescribeInstanceEventNotificationAttributesInput).
    pub fn builder(
    ) -> crate::operation::describe_instance_event_notification_attributes::builders::DescribeInstanceEventNotificationAttributesInputBuilder {
        crate::operation::describe_instance_event_notification_attributes::builders::DescribeInstanceEventNotificationAttributesInputBuilder::default(
        )
    }
}

/// A builder for [`DescribeInstanceEventNotificationAttributesInput`](crate::operation::describe_instance_event_notification_attributes::DescribeInstanceEventNotificationAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstanceEventNotificationAttributesInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DescribeInstanceEventNotificationAttributesInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`DescribeInstanceEventNotificationAttributesInput`](crate::operation::describe_instance_event_notification_attributes::DescribeInstanceEventNotificationAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_instance_event_notification_attributes::DescribeInstanceEventNotificationAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_instance_event_notification_attributes::DescribeInstanceEventNotificationAttributesInput {
                dry_run: self.dry_run,
            },
        )
    }
}
