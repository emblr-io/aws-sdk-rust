// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetNotificationConfigurationOutput {
    /// <p>The ARN of the resource.</p>
    pub arn: ::std::string::String,
    /// <p>The name of the <code>NotificationConfiguration</code>.</p>
    pub name: ::std::string::String,
    /// <p>The description of the <code>NotificationConfiguration</code>.</p>
    pub description: ::std::string::String,
    /// <p>The status of this <code>NotificationConfiguration</code>.</p>
    pub status: crate::types::NotificationConfigurationStatus,
    /// <p>The creation time of the <code>NotificationConfiguration</code>.</p>
    pub creation_time: ::aws_smithy_types::DateTime,
    /// <p>The aggregation preference of the <code>NotificationConfiguration</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>LONG</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for long periods of time (12 hours).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>SHORT</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for short periods of time (5 minutes).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>NONE</code></p>
    /// <ul>
    /// <li>
    /// <p>Don't aggregate notifications.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub aggregation_duration: ::std::option::Option<crate::types::AggregationDuration>,
    _request_id: Option<String>,
}
impl GetNotificationConfigurationOutput {
    /// <p>The ARN of the resource.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The name of the <code>NotificationConfiguration</code>.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the <code>NotificationConfiguration</code>.</p>
    pub fn description(&self) -> &str {
        use std::ops::Deref;
        self.description.deref()
    }
    /// <p>The status of this <code>NotificationConfiguration</code>.</p>
    pub fn status(&self) -> &crate::types::NotificationConfigurationStatus {
        &self.status
    }
    /// <p>The creation time of the <code>NotificationConfiguration</code>.</p>
    pub fn creation_time(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_time
    }
    /// <p>The aggregation preference of the <code>NotificationConfiguration</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>LONG</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for long periods of time (12 hours).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>SHORT</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for short periods of time (5 minutes).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>NONE</code></p>
    /// <ul>
    /// <li>
    /// <p>Don't aggregate notifications.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn aggregation_duration(&self) -> ::std::option::Option<&crate::types::AggregationDuration> {
        self.aggregation_duration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetNotificationConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetNotificationConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetNotificationConfigurationOutput`](crate::operation::get_notification_configuration::GetNotificationConfigurationOutput).
    pub fn builder() -> crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder {
        crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetNotificationConfigurationOutput`](crate::operation::get_notification_configuration::GetNotificationConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetNotificationConfigurationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::NotificationConfigurationStatus>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) aggregation_duration: ::std::option::Option<crate::types::AggregationDuration>,
    _request_id: Option<String>,
}
impl GetNotificationConfigurationOutputBuilder {
    /// <p>The ARN of the resource.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the resource.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the resource.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the <code>NotificationConfiguration</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the <code>NotificationConfiguration</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the <code>NotificationConfiguration</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the <code>NotificationConfiguration</code>.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the <code>NotificationConfiguration</code>.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the <code>NotificationConfiguration</code>.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The status of this <code>NotificationConfiguration</code>.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::NotificationConfigurationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of this <code>NotificationConfiguration</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::NotificationConfigurationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of this <code>NotificationConfiguration</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::NotificationConfigurationStatus> {
        &self.status
    }
    /// <p>The creation time of the <code>NotificationConfiguration</code>.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation time of the <code>NotificationConfiguration</code>.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The creation time of the <code>NotificationConfiguration</code>.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The aggregation preference of the <code>NotificationConfiguration</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>LONG</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for long periods of time (12 hours).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>SHORT</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for short periods of time (5 minutes).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>NONE</code></p>
    /// <ul>
    /// <li>
    /// <p>Don't aggregate notifications.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn aggregation_duration(mut self, input: crate::types::AggregationDuration) -> Self {
        self.aggregation_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregation preference of the <code>NotificationConfiguration</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>LONG</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for long periods of time (12 hours).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>SHORT</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for short periods of time (5 minutes).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>NONE</code></p>
    /// <ul>
    /// <li>
    /// <p>Don't aggregate notifications.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn set_aggregation_duration(mut self, input: ::std::option::Option<crate::types::AggregationDuration>) -> Self {
        self.aggregation_duration = input;
        self
    }
    /// <p>The aggregation preference of the <code>NotificationConfiguration</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>LONG</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for long periods of time (12 hours).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>SHORT</code></p>
    /// <ul>
    /// <li>
    /// <p>Aggregate notifications for short periods of time (5 minutes).</p></li>
    /// </ul></li>
    /// <li>
    /// <p><code>NONE</code></p>
    /// <ul>
    /// <li>
    /// <p>Don't aggregate notifications.</p></li>
    /// </ul></li>
    /// </ul></li>
    /// </ul>
    pub fn get_aggregation_duration(&self) -> &::std::option::Option<crate::types::AggregationDuration> {
        &self.aggregation_duration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetNotificationConfigurationOutput`](crate::operation::get_notification_configuration::GetNotificationConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::arn)
    /// - [`name`](crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::name)
    /// - [`description`](crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::description)
    /// - [`status`](crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::status)
    /// - [`creation_time`](crate::operation::get_notification_configuration::builders::GetNotificationConfigurationOutputBuilder::creation_time)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_notification_configuration::GetNotificationConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_notification_configuration::GetNotificationConfigurationOutput {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building GetNotificationConfigurationOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetNotificationConfigurationOutput",
                )
            })?,
            description: self.description.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "description",
                    "description was not specified but it is required when building GetNotificationConfigurationOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetNotificationConfigurationOutput",
                )
            })?,
            creation_time: self.creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_time",
                    "creation_time was not specified but it is required when building GetNotificationConfigurationOutput",
                )
            })?,
            aggregation_duration: self.aggregation_duration,
            _request_id: self._request_id,
        })
    }
}
