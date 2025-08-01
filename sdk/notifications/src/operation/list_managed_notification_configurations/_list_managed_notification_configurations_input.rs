// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListManagedNotificationConfigurationsInput {
    /// <p>The identifier or ARN of the notification channel to filter configurations by.</p>
    pub channel_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned in this call. Defaults to 20.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The start token for paginated calls. Retrieved from the response of a previous ListManagedNotificationChannelAssociations call. Next token uses Base64 encoding.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListManagedNotificationConfigurationsInput {
    /// <p>The identifier or ARN of the notification channel to filter configurations by.</p>
    pub fn channel_identifier(&self) -> ::std::option::Option<&str> {
        self.channel_identifier.as_deref()
    }
    /// <p>The maximum number of results to be returned in this call. Defaults to 20.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The start token for paginated calls. Retrieved from the response of a previous ListManagedNotificationChannelAssociations call. Next token uses Base64 encoding.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListManagedNotificationConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListManagedNotificationConfigurationsInput`](crate::operation::list_managed_notification_configurations::ListManagedNotificationConfigurationsInput).
    pub fn builder() -> crate::operation::list_managed_notification_configurations::builders::ListManagedNotificationConfigurationsInputBuilder {
        crate::operation::list_managed_notification_configurations::builders::ListManagedNotificationConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListManagedNotificationConfigurationsInput`](crate::operation::list_managed_notification_configurations::ListManagedNotificationConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListManagedNotificationConfigurationsInputBuilder {
    pub(crate) channel_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListManagedNotificationConfigurationsInputBuilder {
    /// <p>The identifier or ARN of the notification channel to filter configurations by.</p>
    pub fn channel_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier or ARN of the notification channel to filter configurations by.</p>
    pub fn set_channel_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_identifier = input;
        self
    }
    /// <p>The identifier or ARN of the notification channel to filter configurations by.</p>
    pub fn get_channel_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_identifier
    }
    /// <p>The maximum number of results to be returned in this call. Defaults to 20.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned in this call. Defaults to 20.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned in this call. Defaults to 20.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The start token for paginated calls. Retrieved from the response of a previous ListManagedNotificationChannelAssociations call. Next token uses Base64 encoding.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The start token for paginated calls. Retrieved from the response of a previous ListManagedNotificationChannelAssociations call. Next token uses Base64 encoding.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The start token for paginated calls. Retrieved from the response of a previous ListManagedNotificationChannelAssociations call. Next token uses Base64 encoding.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListManagedNotificationConfigurationsInput`](crate::operation::list_managed_notification_configurations::ListManagedNotificationConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_managed_notification_configurations::ListManagedNotificationConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_managed_notification_configurations::ListManagedNotificationConfigurationsInput {
                channel_identifier: self.channel_identifier,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
