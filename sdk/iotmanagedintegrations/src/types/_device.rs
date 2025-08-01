// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describe the device using the relevant metadata and supported clusters for device discovery.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Device {
    /// <p>The device id as defined by the connector.</p><note>
    /// <p>This parameter is used for cloud-to-cloud devices only.</p>
    /// </note>
    pub connector_device_id: ::std::string::String,
    /// <p>The name of the device as defined by the connector.</p>
    pub connector_device_name: ::std::option::Option<::std::string::String>,
    /// <p>The capability report for the device.</p>
    pub capability_report: ::std::option::Option<crate::types::MatterCapabilityReport>,
    /// <p>Report of all capabilities supported by the device.</p>
    pub capability_schemas: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>,
    /// <p>The metadata attributes for a device.</p>
    pub device_metadata: ::std::option::Option<::aws_smithy_types::Document>,
}
impl Device {
    /// <p>The device id as defined by the connector.</p><note>
    /// <p>This parameter is used for cloud-to-cloud devices only.</p>
    /// </note>
    pub fn connector_device_id(&self) -> &str {
        use std::ops::Deref;
        self.connector_device_id.deref()
    }
    /// <p>The name of the device as defined by the connector.</p>
    pub fn connector_device_name(&self) -> ::std::option::Option<&str> {
        self.connector_device_name.as_deref()
    }
    /// <p>The capability report for the device.</p>
    pub fn capability_report(&self) -> ::std::option::Option<&crate::types::MatterCapabilityReport> {
        self.capability_report.as_ref()
    }
    /// <p>Report of all capabilities supported by the device.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capability_schemas.is_none()`.
    pub fn capability_schemas(&self) -> &[crate::types::CapabilitySchemaItem] {
        self.capability_schemas.as_deref().unwrap_or_default()
    }
    /// <p>The metadata attributes for a device.</p>
    pub fn device_metadata(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.device_metadata.as_ref()
    }
}
impl ::std::fmt::Debug for Device {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Device");
        formatter.field("connector_device_id", &"*** Sensitive Data Redacted ***");
        formatter.field("connector_device_name", &"*** Sensitive Data Redacted ***");
        formatter.field("capability_report", &self.capability_report);
        formatter.field("capability_schemas", &self.capability_schemas);
        formatter.field("device_metadata", &self.device_metadata);
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
    pub(crate) connector_device_id: ::std::option::Option<::std::string::String>,
    pub(crate) connector_device_name: ::std::option::Option<::std::string::String>,
    pub(crate) capability_report: ::std::option::Option<crate::types::MatterCapabilityReport>,
    pub(crate) capability_schemas: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>,
    pub(crate) device_metadata: ::std::option::Option<::aws_smithy_types::Document>,
}
impl DeviceBuilder {
    /// <p>The device id as defined by the connector.</p><note>
    /// <p>This parameter is used for cloud-to-cloud devices only.</p>
    /// </note>
    /// This field is required.
    pub fn connector_device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device id as defined by the connector.</p><note>
    /// <p>This parameter is used for cloud-to-cloud devices only.</p>
    /// </note>
    pub fn set_connector_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_device_id = input;
        self
    }
    /// <p>The device id as defined by the connector.</p><note>
    /// <p>This parameter is used for cloud-to-cloud devices only.</p>
    /// </note>
    pub fn get_connector_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_device_id
    }
    /// <p>The name of the device as defined by the connector.</p>
    pub fn connector_device_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_device_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the device as defined by the connector.</p>
    pub fn set_connector_device_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_device_name = input;
        self
    }
    /// <p>The name of the device as defined by the connector.</p>
    pub fn get_connector_device_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_device_name
    }
    /// <p>The capability report for the device.</p>
    /// This field is required.
    pub fn capability_report(mut self, input: crate::types::MatterCapabilityReport) -> Self {
        self.capability_report = ::std::option::Option::Some(input);
        self
    }
    /// <p>The capability report for the device.</p>
    pub fn set_capability_report(mut self, input: ::std::option::Option<crate::types::MatterCapabilityReport>) -> Self {
        self.capability_report = input;
        self
    }
    /// <p>The capability report for the device.</p>
    pub fn get_capability_report(&self) -> &::std::option::Option<crate::types::MatterCapabilityReport> {
        &self.capability_report
    }
    /// Appends an item to `capability_schemas`.
    ///
    /// To override the contents of this collection use [`set_capability_schemas`](Self::set_capability_schemas).
    ///
    /// <p>Report of all capabilities supported by the device.</p>
    pub fn capability_schemas(mut self, input: crate::types::CapabilitySchemaItem) -> Self {
        let mut v = self.capability_schemas.unwrap_or_default();
        v.push(input);
        self.capability_schemas = ::std::option::Option::Some(v);
        self
    }
    /// <p>Report of all capabilities supported by the device.</p>
    pub fn set_capability_schemas(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>>) -> Self {
        self.capability_schemas = input;
        self
    }
    /// <p>Report of all capabilities supported by the device.</p>
    pub fn get_capability_schemas(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CapabilitySchemaItem>> {
        &self.capability_schemas
    }
    /// <p>The metadata attributes for a device.</p>
    pub fn device_metadata(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.device_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata attributes for a device.</p>
    pub fn set_device_metadata(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.device_metadata = input;
        self
    }
    /// <p>The metadata attributes for a device.</p>
    pub fn get_device_metadata(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.device_metadata
    }
    /// Consumes the builder and constructs a [`Device`](crate::types::Device).
    /// This method will fail if any of the following fields are not set:
    /// - [`connector_device_id`](crate::types::builders::DeviceBuilder::connector_device_id)
    pub fn build(self) -> ::std::result::Result<crate::types::Device, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Device {
            connector_device_id: self.connector_device_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connector_device_id",
                    "connector_device_id was not specified but it is required when building Device",
                )
            })?,
            connector_device_name: self.connector_device_name,
            capability_report: self.capability_report,
            capability_schemas: self.capability_schemas,
            device_metadata: self.device_metadata,
        })
    }
}
impl ::std::fmt::Debug for DeviceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DeviceBuilder");
        formatter.field("connector_device_id", &"*** Sensitive Data Redacted ***");
        formatter.field("connector_device_name", &"*** Sensitive Data Redacted ***");
        formatter.field("capability_report", &self.capability_report);
        formatter.field("capability_schemas", &self.capability_schemas);
        formatter.field("device_metadata", &self.device_metadata);
        formatter.finish()
    }
}
