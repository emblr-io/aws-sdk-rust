// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a device.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Device {
    /// <p>The ID of the device.</p>
    pub device_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the device.</p>
    pub device_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the global network.</p>
    pub global_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services location of the device.</p>
    pub aws_location: ::std::option::Option<crate::types::AwsLocation>,
    /// <p>The description of the device.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The device type.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The device vendor.</p>
    pub vendor: ::std::option::Option<::std::string::String>,
    /// <p>The device model.</p>
    pub model: ::std::option::Option<::std::string::String>,
    /// <p>The device serial number.</p>
    pub serial_number: ::std::option::Option<::std::string::String>,
    /// <p>The site location.</p>
    pub location: ::std::option::Option<crate::types::Location>,
    /// <p>The site ID.</p>
    pub site_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the site was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The device state.</p>
    pub state: ::std::option::Option<crate::types::DeviceState>,
    /// <p>The tags for the device.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl Device {
    /// <p>The ID of the device.</p>
    pub fn device_id(&self) -> ::std::option::Option<&str> {
        self.device_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the device.</p>
    pub fn device_arn(&self) -> ::std::option::Option<&str> {
        self.device_arn.as_deref()
    }
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(&self) -> ::std::option::Option<&str> {
        self.global_network_id.as_deref()
    }
    /// <p>The Amazon Web Services location of the device.</p>
    pub fn aws_location(&self) -> ::std::option::Option<&crate::types::AwsLocation> {
        self.aws_location.as_ref()
    }
    /// <p>The description of the device.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The device type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The device vendor.</p>
    pub fn vendor(&self) -> ::std::option::Option<&str> {
        self.vendor.as_deref()
    }
    /// <p>The device model.</p>
    pub fn model(&self) -> ::std::option::Option<&str> {
        self.model.as_deref()
    }
    /// <p>The device serial number.</p>
    pub fn serial_number(&self) -> ::std::option::Option<&str> {
        self.serial_number.as_deref()
    }
    /// <p>The site location.</p>
    pub fn location(&self) -> ::std::option::Option<&crate::types::Location> {
        self.location.as_ref()
    }
    /// <p>The site ID.</p>
    pub fn site_id(&self) -> ::std::option::Option<&str> {
        self.site_id.as_deref()
    }
    /// <p>The date and time that the site was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The device state.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::DeviceState> {
        self.state.as_ref()
    }
    /// <p>The tags for the device.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for Device {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Device");
        formatter.field("device_id", &self.device_id);
        formatter.field("device_arn", &self.device_arn);
        formatter.field("global_network_id", &self.global_network_id);
        formatter.field("aws_location", &self.aws_location);
        formatter.field("description", &self.description);
        formatter.field("r#type", &self.r#type);
        formatter.field("vendor", &self.vendor);
        formatter.field("model", &self.model);
        formatter.field("serial_number", &self.serial_number);
        formatter.field("location", &"*** Sensitive Data Redacted ***");
        formatter.field("site_id", &self.site_id);
        formatter.field("created_at", &self.created_at);
        formatter.field("state", &self.state);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl Device {
    /// Creates a new builder-style object to manufacture [`Device`](crate::types::Device).
    pub fn builder() -> crate::types::builders::DeviceBuilder {
        crate::types::builders::DeviceBuilder::default()
    }
}

/// A builder for [`Device`](crate::types::Device).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DeviceBuilder {
    pub(crate) device_id: ::std::option::Option<::std::string::String>,
    pub(crate) device_arn: ::std::option::Option<::std::string::String>,
    pub(crate) global_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_location: ::std::option::Option<crate::types::AwsLocation>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) vendor: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<::std::string::String>,
    pub(crate) serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) location: ::std::option::Option<crate::types::Location>,
    pub(crate) site_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::DeviceState>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl DeviceBuilder {
    /// <p>The ID of the device.</p>
    pub fn device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the device.</p>
    pub fn set_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_id = input;
        self
    }
    /// <p>The ID of the device.</p>
    pub fn get_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_id
    }
    /// <p>The Amazon Resource Name (ARN) of the device.</p>
    pub fn device_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device.</p>
    pub fn set_device_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the device.</p>
    pub fn get_device_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_arn
    }
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn set_global_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_network_id = input;
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn get_global_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_network_id
    }
    /// <p>The Amazon Web Services location of the device.</p>
    pub fn aws_location(mut self, input: crate::types::AwsLocation) -> Self {
        self.aws_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Web Services location of the device.</p>
    pub fn set_aws_location(mut self, input: ::std::option::Option<crate::types::AwsLocation>) -> Self {
        self.aws_location = input;
        self
    }
    /// <p>The Amazon Web Services location of the device.</p>
    pub fn get_aws_location(&self) -> &::std::option::Option<crate::types::AwsLocation> {
        &self.aws_location
    }
    /// <p>The description of the device.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the device.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the device.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The device type.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The device type.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The device vendor.</p>
    pub fn vendor(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vendor = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device vendor.</p>
    pub fn set_vendor(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vendor = input;
        self
    }
    /// <p>The device vendor.</p>
    pub fn get_vendor(&self) -> &::std::option::Option<::std::string::String> {
        &self.vendor
    }
    /// <p>The device model.</p>
    pub fn model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device model.</p>
    pub fn set_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model = input;
        self
    }
    /// <p>The device model.</p>
    pub fn get_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.model
    }
    /// <p>The device serial number.</p>
    pub fn serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device serial number.</p>
    pub fn set_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.serial_number = input;
        self
    }
    /// <p>The device serial number.</p>
    pub fn get_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.serial_number
    }
    /// <p>The site location.</p>
    pub fn location(mut self, input: crate::types::Location) -> Self {
        self.location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The site location.</p>
    pub fn set_location(mut self, input: ::std::option::Option<crate::types::Location>) -> Self {
        self.location = input;
        self
    }
    /// <p>The site location.</p>
    pub fn get_location(&self) -> &::std::option::Option<crate::types::Location> {
        &self.location
    }
    /// <p>The site ID.</p>
    pub fn site_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.site_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The site ID.</p>
    pub fn set_site_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.site_id = input;
        self
    }
    /// <p>The site ID.</p>
    pub fn get_site_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.site_id
    }
    /// <p>The date and time that the site was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the site was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the site was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The device state.</p>
    pub fn state(mut self, input: crate::types::DeviceState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The device state.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::DeviceState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The device state.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::DeviceState> {
        &self.state
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the device.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags for the device.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the device.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`Device`](crate::types::Device).
    pub fn build(self) -> crate::types::Device {
        crate::types::Device {
            device_id: self.device_id,
            device_arn: self.device_arn,
            global_network_id: self.global_network_id,
            aws_location: self.aws_location,
            description: self.description,
            r#type: self.r#type,
            vendor: self.vendor,
            model: self.model,
            serial_number: self.serial_number,
            location: self.location,
            site_id: self.site_id,
            created_at: self.created_at,
            state: self.state,
            tags: self.tags,
        }
    }
}
impl ::std::fmt::Debug for DeviceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeviceBuilder");
        formatter.field("device_id", &self.device_id);
        formatter.field("device_arn", &self.device_arn);
        formatter.field("global_network_id", &self.global_network_id);
        formatter.field("aws_location", &self.aws_location);
        formatter.field("description", &self.description);
        formatter.field("r#type", &self.r#type);
        formatter.field("vendor", &self.vendor);
        formatter.field("model", &self.model);
        formatter.field("serial_number", &self.serial_number);
        formatter.field("location", &"*** Sensitive Data Redacted ***");
        formatter.field("site_id", &self.site_id);
        formatter.field("created_at", &self.created_at);
        formatter.field("state", &self.state);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
