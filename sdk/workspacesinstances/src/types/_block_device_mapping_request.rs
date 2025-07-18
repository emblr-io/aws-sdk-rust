// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines device mapping for WorkSpace Instance storage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BlockDeviceMappingRequest {
    /// <p>Name of the device for storage mapping.</p>
    pub device_name: ::std::option::Option<::std::string::String>,
    /// <p>EBS volume configuration for the device.</p>
    pub ebs: ::std::option::Option<crate::types::EbsBlockDevice>,
    /// <p>Indicates device should not be mapped.</p>
    pub no_device: ::std::option::Option<::std::string::String>,
    /// <p>Virtual device name for ephemeral storage.</p>
    pub virtual_name: ::std::option::Option<::std::string::String>,
}
impl BlockDeviceMappingRequest {
    /// <p>Name of the device for storage mapping.</p>
    pub fn device_name(&self) -> ::std::option::Option<&str> {
        self.device_name.as_deref()
    }
    /// <p>EBS volume configuration for the device.</p>
    pub fn ebs(&self) -> ::std::option::Option<&crate::types::EbsBlockDevice> {
        self.ebs.as_ref()
    }
    /// <p>Indicates device should not be mapped.</p>
    pub fn no_device(&self) -> ::std::option::Option<&str> {
        self.no_device.as_deref()
    }
    /// <p>Virtual device name for ephemeral storage.</p>
    pub fn virtual_name(&self) -> ::std::option::Option<&str> {
        self.virtual_name.as_deref()
    }
}
impl BlockDeviceMappingRequest {
    /// Creates a new builder-style object to manufacture [`BlockDeviceMappingRequest`](crate::types::BlockDeviceMappingRequest).
    pub fn builder() -> crate::types::builders::BlockDeviceMappingRequestBuilder {
        crate::types::builders::BlockDeviceMappingRequestBuilder::default()
    }
}

/// A builder for [`BlockDeviceMappingRequest`](crate::types::BlockDeviceMappingRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BlockDeviceMappingRequestBuilder {
    pub(crate) device_name: ::std::option::Option<::std::string::String>,
    pub(crate) ebs: ::std::option::Option<crate::types::EbsBlockDevice>,
    pub(crate) no_device: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_name: ::std::option::Option<::std::string::String>,
}
impl BlockDeviceMappingRequestBuilder {
    /// <p>Name of the device for storage mapping.</p>
    pub fn device_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the device for storage mapping.</p>
    pub fn set_device_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_name = input;
        self
    }
    /// <p>Name of the device for storage mapping.</p>
    pub fn get_device_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_name
    }
    /// <p>EBS volume configuration for the device.</p>
    pub fn ebs(mut self, input: crate::types::EbsBlockDevice) -> Self {
        self.ebs = ::std::option::Option::Some(input);
        self
    }
    /// <p>EBS volume configuration for the device.</p>
    pub fn set_ebs(mut self, input: ::std::option::Option<crate::types::EbsBlockDevice>) -> Self {
        self.ebs = input;
        self
    }
    /// <p>EBS volume configuration for the device.</p>
    pub fn get_ebs(&self) -> &::std::option::Option<crate::types::EbsBlockDevice> {
        &self.ebs
    }
    /// <p>Indicates device should not be mapped.</p>
    pub fn no_device(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.no_device = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates device should not be mapped.</p>
    pub fn set_no_device(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.no_device = input;
        self
    }
    /// <p>Indicates device should not be mapped.</p>
    pub fn get_no_device(&self) -> &::std::option::Option<::std::string::String> {
        &self.no_device
    }
    /// <p>Virtual device name for ephemeral storage.</p>
    pub fn virtual_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Virtual device name for ephemeral storage.</p>
    pub fn set_virtual_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_name = input;
        self
    }
    /// <p>Virtual device name for ephemeral storage.</p>
    pub fn get_virtual_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_name
    }
    /// Consumes the builder and constructs a [`BlockDeviceMappingRequest`](crate::types::BlockDeviceMappingRequest).
    pub fn build(self) -> crate::types::BlockDeviceMappingRequest {
        crate::types::BlockDeviceMappingRequest {
            device_name: self.device_name,
            ebs: self.ebs,
            no_device: self.no_device,
            virtual_name: self.virtual_name,
        }
    }
}
