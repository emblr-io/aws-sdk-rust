// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAddonSubscriptionOutput {
    /// <p>The name of the Add On for the subscription.</p>
    pub addon_name: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) for the subscription.</p>
    pub addon_subscription_arn: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the Add On subscription was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetAddonSubscriptionOutput {
    /// <p>The name of the Add On for the subscription.</p>
    pub fn addon_name(&self) -> ::std::option::Option<&str> {
        self.addon_name.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) for the subscription.</p>
    pub fn addon_subscription_arn(&self) -> ::std::option::Option<&str> {
        self.addon_subscription_arn.as_deref()
    }
    /// <p>The timestamp of when the Add On subscription was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAddonSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAddonSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`GetAddonSubscriptionOutput`](crate::operation::get_addon_subscription::GetAddonSubscriptionOutput).
    pub fn builder() -> crate::operation::get_addon_subscription::builders::GetAddonSubscriptionOutputBuilder {
        crate::operation::get_addon_subscription::builders::GetAddonSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`GetAddonSubscriptionOutput`](crate::operation::get_addon_subscription::GetAddonSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAddonSubscriptionOutputBuilder {
    pub(crate) addon_name: ::std::option::Option<::std::string::String>,
    pub(crate) addon_subscription_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetAddonSubscriptionOutputBuilder {
    /// <p>The name of the Add On for the subscription.</p>
    pub fn addon_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Add On for the subscription.</p>
    pub fn set_addon_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_name = input;
        self
    }
    /// <p>The name of the Add On for the subscription.</p>
    pub fn get_addon_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_name
    }
    /// <p>Amazon Resource Name (ARN) for the subscription.</p>
    pub fn addon_subscription_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.addon_subscription_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) for the subscription.</p>
    pub fn set_addon_subscription_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.addon_subscription_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) for the subscription.</p>
    pub fn get_addon_subscription_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.addon_subscription_arn
    }
    /// <p>The timestamp of when the Add On subscription was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the Add On subscription was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The timestamp of when the Add On subscription was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAddonSubscriptionOutput`](crate::operation::get_addon_subscription::GetAddonSubscriptionOutput).
    pub fn build(self) -> crate::operation::get_addon_subscription::GetAddonSubscriptionOutput {
        crate::operation::get_addon_subscription::GetAddonSubscriptionOutput {
            addon_name: self.addon_name,
            addon_subscription_arn: self.addon_subscription_arn,
            created_timestamp: self.created_timestamp,
            _request_id: self._request_id,
        }
    }
}
