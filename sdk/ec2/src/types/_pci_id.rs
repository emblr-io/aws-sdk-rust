// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the data that identifies an Amazon FPGA image (AFI) on the PCI bus.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PciId {
    /// <p>The ID of the device.</p>
    pub device_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the vendor.</p>
    pub vendor_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subsystem.</p>
    pub subsystem_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the vendor for the subsystem.</p>
    pub subsystem_vendor_id: ::std::option::Option<::std::string::String>,
}
impl PciId {
    /// <p>The ID of the device.</p>
    pub fn device_id(&self) -> ::std::option::Option<&str> {
        self.device_id.as_deref()
    }
    /// <p>The ID of the vendor.</p>
    pub fn vendor_id(&self) -> ::std::option::Option<&str> {
        self.vendor_id.as_deref()
    }
    /// <p>The ID of the subsystem.</p>
    pub fn subsystem_id(&self) -> ::std::option::Option<&str> {
        self.subsystem_id.as_deref()
    }
    /// <p>The ID of the vendor for the subsystem.</p>
    pub fn subsystem_vendor_id(&self) -> ::std::option::Option<&str> {
        self.subsystem_vendor_id.as_deref()
    }
}
impl PciId {
    /// Creates a new builder-style object to manufacture [`PciId`](crate::types::PciId).
    pub fn builder() -> crate::types::builders::PciIdBuilder {
        crate::types::builders::PciIdBuilder::default()
    }
}

/// A builder for [`PciId`](crate::types::PciId).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PciIdBuilder {
    pub(crate) device_id: ::std::option::Option<::std::string::String>,
    pub(crate) vendor_id: ::std::option::Option<::std::string::String>,
    pub(crate) subsystem_id: ::std::option::Option<::std::string::String>,
    pub(crate) subsystem_vendor_id: ::std::option::Option<::std::string::String>,
}
impl PciIdBuilder {
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
    /// <p>The ID of the vendor.</p>
    pub fn vendor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vendor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the vendor.</p>
    pub fn set_vendor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vendor_id = input;
        self
    }
    /// <p>The ID of the vendor.</p>
    pub fn get_vendor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vendor_id
    }
    /// <p>The ID of the subsystem.</p>
    pub fn subsystem_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subsystem_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subsystem.</p>
    pub fn set_subsystem_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subsystem_id = input;
        self
    }
    /// <p>The ID of the subsystem.</p>
    pub fn get_subsystem_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subsystem_id
    }
    /// <p>The ID of the vendor for the subsystem.</p>
    pub fn subsystem_vendor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subsystem_vendor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the vendor for the subsystem.</p>
    pub fn set_subsystem_vendor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subsystem_vendor_id = input;
        self
    }
    /// <p>The ID of the vendor for the subsystem.</p>
    pub fn get_subsystem_vendor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subsystem_vendor_id
    }
    /// Consumes the builder and constructs a [`PciId`](crate::types::PciId).
    pub fn build(self) -> crate::types::PciId {
        crate::types::PciId {
            device_id: self.device_id,
            vendor_id: self.vendor_id,
            subsystem_id: self.subsystem_id,
            subsystem_vendor_id: self.subsystem_vendor_id,
        }
    }
}
