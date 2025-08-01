// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAccessLogSubscriptionOutput {
    /// <p>The ID of the access log subscription.</p>
    pub id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the access log subscription.</p>
    pub arn: ::std::string::String,
    /// <p>The ID of the service network or service.</p>
    pub resource_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the service network or service.</p>
    pub resource_arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the access log destination.</p>
    pub destination_arn: ::std::string::String,
    /// <p>The log type for the service network.</p>
    pub service_network_log_type: ::std::option::Option<crate::types::ServiceNetworkLogType>,
    /// <p>The date and time that the access log subscription was created, in ISO-8601 format.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The date and time that the access log subscription was last updated, in ISO-8601 format.</p>
    pub last_updated_at: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl GetAccessLogSubscriptionOutput {
    /// <p>The ID of the access log subscription.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the access log subscription.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The ID of the service network or service.</p>
    pub fn resource_id(&self) -> &str {
        use std::ops::Deref;
        self.resource_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the service network or service.</p>
    pub fn resource_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the access log destination.</p>
    pub fn destination_arn(&self) -> &str {
        use std::ops::Deref;
        self.destination_arn.deref()
    }
    /// <p>The log type for the service network.</p>
    pub fn service_network_log_type(&self) -> ::std::option::Option<&crate::types::ServiceNetworkLogType> {
        self.service_network_log_type.as_ref()
    }
    /// <p>The date and time that the access log subscription was created, in ISO-8601 format.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The date and time that the access log subscription was last updated, in ISO-8601 format.</p>
    pub fn last_updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_at
    }
}
impl ::aws_types::request_id::RequestId for GetAccessLogSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAccessLogSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`GetAccessLogSubscriptionOutput`](crate::operation::get_access_log_subscription::GetAccessLogSubscriptionOutput).
    pub fn builder() -> crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder {
        crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`GetAccessLogSubscriptionOutput`](crate::operation::get_access_log_subscription::GetAccessLogSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAccessLogSubscriptionOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) destination_arn: ::std::option::Option<::std::string::String>,
    pub(crate) service_network_log_type: ::std::option::Option<crate::types::ServiceNetworkLogType>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetAccessLogSubscriptionOutputBuilder {
    /// <p>The ID of the access log subscription.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the access log subscription.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the access log subscription.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the access log subscription.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access log subscription.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access log subscription.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the service network or service.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service network or service.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the service network or service.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The Amazon Resource Name (ARN) of the service network or service.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service network or service.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service network or service.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the access log destination.</p>
    /// This field is required.
    pub fn destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access log destination.</p>
    pub fn set_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access log destination.</p>
    pub fn get_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_arn
    }
    /// <p>The log type for the service network.</p>
    pub fn service_network_log_type(mut self, input: crate::types::ServiceNetworkLogType) -> Self {
        self.service_network_log_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log type for the service network.</p>
    pub fn set_service_network_log_type(mut self, input: ::std::option::Option<crate::types::ServiceNetworkLogType>) -> Self {
        self.service_network_log_type = input;
        self
    }
    /// <p>The log type for the service network.</p>
    pub fn get_service_network_log_type(&self) -> &::std::option::Option<crate::types::ServiceNetworkLogType> {
        &self.service_network_log_type
    }
    /// <p>The date and time that the access log subscription was created, in ISO-8601 format.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the access log subscription was created, in ISO-8601 format.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the access log subscription was created, in ISO-8601 format.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time that the access log subscription was last updated, in ISO-8601 format.</p>
    /// This field is required.
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the access log subscription was last updated, in ISO-8601 format.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The date and time that the access log subscription was last updated, in ISO-8601 format.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAccessLogSubscriptionOutput`](crate::operation::get_access_log_subscription::GetAccessLogSubscriptionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::id)
    /// - [`arn`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::arn)
    /// - [`resource_id`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::resource_id)
    /// - [`resource_arn`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::resource_arn)
    /// - [`destination_arn`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::destination_arn)
    /// - [`created_at`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::created_at)
    /// - [`last_updated_at`](crate::operation::get_access_log_subscription::builders::GetAccessLogSubscriptionOutputBuilder::last_updated_at)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_access_log_subscription::GetAccessLogSubscriptionOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_access_log_subscription::GetAccessLogSubscriptionOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            resource_id: self.resource_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_id",
                    "resource_id was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            resource_arn: self.resource_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_arn",
                    "resource_arn was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            destination_arn: self.destination_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "destination_arn",
                    "destination_arn was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            service_network_log_type: self.service_network_log_type,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            last_updated_at: self.last_updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_at",
                    "last_updated_at was not specified but it is required when building GetAccessLogSubscriptionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
