// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Location rule action sends device location updates from an MQTT message to an Amazon Location tracker resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LocationAction {
    /// <p>The IAM role that grants permission to write to the Amazon Location resource.</p>
    pub role_arn: ::std::string::String,
    /// <p>The name of the tracker resource in Amazon Location in which the location is updated.</p>
    pub tracker_name: ::std::string::String,
    /// <p>The unique ID of the device providing the location data.</p>
    pub device_id: ::std::string::String,
    /// <p>The time that the location data was sampled. The default value is the time the MQTT message was processed.</p>
    pub timestamp: ::std::option::Option<crate::types::LocationTimestamp>,
    /// <p>A string that evaluates to a double value that represents the latitude of the device's location.</p>
    pub latitude: ::std::string::String,
    /// <p>A string that evaluates to a double value that represents the longitude of the device's location.</p>
    pub longitude: ::std::string::String,
}
impl LocationAction {
    /// <p>The IAM role that grants permission to write to the Amazon Location resource.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The name of the tracker resource in Amazon Location in which the location is updated.</p>
    pub fn tracker_name(&self) -> &str {
        use std::ops::Deref;
        self.tracker_name.deref()
    }
    /// <p>The unique ID of the device providing the location data.</p>
    pub fn device_id(&self) -> &str {
        use std::ops::Deref;
        self.device_id.deref()
    }
    /// <p>The time that the location data was sampled. The default value is the time the MQTT message was processed.</p>
    pub fn timestamp(&self) -> ::std::option::Option<&crate::types::LocationTimestamp> {
        self.timestamp.as_ref()
    }
    /// <p>A string that evaluates to a double value that represents the latitude of the device's location.</p>
    pub fn latitude(&self) -> &str {
        use std::ops::Deref;
        self.latitude.deref()
    }
    /// <p>A string that evaluates to a double value that represents the longitude of the device's location.</p>
    pub fn longitude(&self) -> &str {
        use std::ops::Deref;
        self.longitude.deref()
    }
}
impl LocationAction {
    /// Creates a new builder-style object to manufacture [`LocationAction`](crate::types::LocationAction).
    pub fn builder() -> crate::types::builders::LocationActionBuilder {
        crate::types::builders::LocationActionBuilder::default()
    }
}

/// A builder for [`LocationAction`](crate::types::LocationAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LocationActionBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tracker_name: ::std::option::Option<::std::string::String>,
    pub(crate) device_id: ::std::option::Option<::std::string::String>,
    pub(crate) timestamp: ::std::option::Option<crate::types::LocationTimestamp>,
    pub(crate) latitude: ::std::option::Option<::std::string::String>,
    pub(crate) longitude: ::std::option::Option<::std::string::String>,
}
impl LocationActionBuilder {
    /// <p>The IAM role that grants permission to write to the Amazon Location resource.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role that grants permission to write to the Amazon Location resource.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The IAM role that grants permission to write to the Amazon Location resource.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The name of the tracker resource in Amazon Location in which the location is updated.</p>
    /// This field is required.
    pub fn tracker_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tracker_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the tracker resource in Amazon Location in which the location is updated.</p>
    pub fn set_tracker_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tracker_name = input;
        self
    }
    /// <p>The name of the tracker resource in Amazon Location in which the location is updated.</p>
    pub fn get_tracker_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.tracker_name
    }
    /// <p>The unique ID of the device providing the location data.</p>
    /// This field is required.
    pub fn device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the device providing the location data.</p>
    pub fn set_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_id = input;
        self
    }
    /// <p>The unique ID of the device providing the location data.</p>
    pub fn get_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_id
    }
    /// <p>The time that the location data was sampled. The default value is the time the MQTT message was processed.</p>
    pub fn timestamp(mut self, input: crate::types::LocationTimestamp) -> Self {
        self.timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the location data was sampled. The default value is the time the MQTT message was processed.</p>
    pub fn set_timestamp(mut self, input: ::std::option::Option<crate::types::LocationTimestamp>) -> Self {
        self.timestamp = input;
        self
    }
    /// <p>The time that the location data was sampled. The default value is the time the MQTT message was processed.</p>
    pub fn get_timestamp(&self) -> &::std::option::Option<crate::types::LocationTimestamp> {
        &self.timestamp
    }
    /// <p>A string that evaluates to a double value that represents the latitude of the device's location.</p>
    /// This field is required.
    pub fn latitude(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latitude = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that evaluates to a double value that represents the latitude of the device's location.</p>
    pub fn set_latitude(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latitude = input;
        self
    }
    /// <p>A string that evaluates to a double value that represents the latitude of the device's location.</p>
    pub fn get_latitude(&self) -> &::std::option::Option<::std::string::String> {
        &self.latitude
    }
    /// <p>A string that evaluates to a double value that represents the longitude of the device's location.</p>
    /// This field is required.
    pub fn longitude(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.longitude = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that evaluates to a double value that represents the longitude of the device's location.</p>
    pub fn set_longitude(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.longitude = input;
        self
    }
    /// <p>A string that evaluates to a double value that represents the longitude of the device's location.</p>
    pub fn get_longitude(&self) -> &::std::option::Option<::std::string::String> {
        &self.longitude
    }
    /// Consumes the builder and constructs a [`LocationAction`](crate::types::LocationAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_arn`](crate::types::builders::LocationActionBuilder::role_arn)
    /// - [`tracker_name`](crate::types::builders::LocationActionBuilder::tracker_name)
    /// - [`device_id`](crate::types::builders::LocationActionBuilder::device_id)
    /// - [`latitude`](crate::types::builders::LocationActionBuilder::latitude)
    /// - [`longitude`](crate::types::builders::LocationActionBuilder::longitude)
    pub fn build(self) -> ::std::result::Result<crate::types::LocationAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LocationAction {
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building LocationAction",
                )
            })?,
            tracker_name: self.tracker_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tracker_name",
                    "tracker_name was not specified but it is required when building LocationAction",
                )
            })?,
            device_id: self.device_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "device_id",
                    "device_id was not specified but it is required when building LocationAction",
                )
            })?,
            timestamp: self.timestamp,
            latitude: self.latitude.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "latitude",
                    "latitude was not specified but it is required when building LocationAction",
                )
            })?,
            longitude: self.longitude.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "longitude",
                    "longitude was not specified but it is required when building LocationAction",
                )
            })?,
        })
    }
}
