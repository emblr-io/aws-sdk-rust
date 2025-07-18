// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetWirelessDeviceInput {
    /// <p>The identifier of the wireless device to get.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of identifier used in <code>identifier</code>.</p>
    pub identifier_type: ::std::option::Option<crate::types::WirelessDeviceIdType>,
}
impl GetWirelessDeviceInput {
    /// <p>The identifier of the wireless device to get.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The type of identifier used in <code>identifier</code>.</p>
    pub fn identifier_type(&self) -> ::std::option::Option<&crate::types::WirelessDeviceIdType> {
        self.identifier_type.as_ref()
    }
}
impl GetWirelessDeviceInput {
    /// Creates a new builder-style object to manufacture [`GetWirelessDeviceInput`](crate::operation::get_wireless_device::GetWirelessDeviceInput).
    pub fn builder() -> crate::operation::get_wireless_device::builders::GetWirelessDeviceInputBuilder {
        crate::operation::get_wireless_device::builders::GetWirelessDeviceInputBuilder::default()
    }
}

/// A builder for [`GetWirelessDeviceInput`](crate::operation::get_wireless_device::GetWirelessDeviceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetWirelessDeviceInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier_type: ::std::option::Option<crate::types::WirelessDeviceIdType>,
}
impl GetWirelessDeviceInputBuilder {
    /// <p>The identifier of the wireless device to get.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the wireless device to get.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the wireless device to get.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The type of identifier used in <code>identifier</code>.</p>
    /// This field is required.
    pub fn identifier_type(mut self, input: crate::types::WirelessDeviceIdType) -> Self {
        self.identifier_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of identifier used in <code>identifier</code>.</p>
    pub fn set_identifier_type(mut self, input: ::std::option::Option<crate::types::WirelessDeviceIdType>) -> Self {
        self.identifier_type = input;
        self
    }
    /// <p>The type of identifier used in <code>identifier</code>.</p>
    pub fn get_identifier_type(&self) -> &::std::option::Option<crate::types::WirelessDeviceIdType> {
        &self.identifier_type
    }
    /// Consumes the builder and constructs a [`GetWirelessDeviceInput`](crate::operation::get_wireless_device::GetWirelessDeviceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_wireless_device::GetWirelessDeviceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_wireless_device::GetWirelessDeviceInput {
            identifier: self.identifier,
            identifier_type: self.identifier_type,
        })
    }
}
