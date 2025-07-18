// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a block device mapping. This data type maps directly to the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a> data type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BlockDeviceMapping {
    /// <p>The device name that is exposed to the instance, such as <code>/dev/sdh</code>. For the root device, you can use the explicit device name or you can set this parameter to <code>ROOT_DEVICE</code> and OpsWorks Stacks will provide the correct device name.</p>
    pub device_name: ::std::option::Option<::std::string::String>,
    /// <p>Suppresses the specified device included in the AMI's block device mapping.</p>
    pub no_device: ::std::option::Option<::std::string::String>,
    /// <p>The virtual device name. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a>.</p>
    pub virtual_name: ::std::option::Option<::std::string::String>,
    /// <p>An <code>EBSBlockDevice</code> that defines how to configure an Amazon EBS volume when the instance is launched.</p>
    pub ebs: ::std::option::Option<crate::types::EbsBlockDevice>,
}
impl BlockDeviceMapping {
    /// <p>The device name that is exposed to the instance, such as <code>/dev/sdh</code>. For the root device, you can use the explicit device name or you can set this parameter to <code>ROOT_DEVICE</code> and OpsWorks Stacks will provide the correct device name.</p>
    pub fn device_name(&self) -> ::std::option::Option<&str> {
        self.device_name.as_deref()
    }
    /// <p>Suppresses the specified device included in the AMI's block device mapping.</p>
    pub fn no_device(&self) -> ::std::option::Option<&str> {
        self.no_device.as_deref()
    }
    /// <p>The virtual device name. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a>.</p>
    pub fn virtual_name(&self) -> ::std::option::Option<&str> {
        self.virtual_name.as_deref()
    }
    /// <p>An <code>EBSBlockDevice</code> that defines how to configure an Amazon EBS volume when the instance is launched.</p>
    pub fn ebs(&self) -> ::std::option::Option<&crate::types::EbsBlockDevice> {
        self.ebs.as_ref()
    }
}
impl BlockDeviceMapping {
    /// Creates a new builder-style object to manufacture [`BlockDeviceMapping`](crate::types::BlockDeviceMapping).
    pub fn builder() -> crate::types::builders::BlockDeviceMappingBuilder {
        crate::types::builders::BlockDeviceMappingBuilder::default()
    }
}

/// A builder for [`BlockDeviceMapping`](crate::types::BlockDeviceMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BlockDeviceMappingBuilder {
    pub(crate) device_name: ::std::option::Option<::std::string::String>,
    pub(crate) no_device: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_name: ::std::option::Option<::std::string::String>,
    pub(crate) ebs: ::std::option::Option<crate::types::EbsBlockDevice>,
}
impl BlockDeviceMappingBuilder {
    /// <p>The device name that is exposed to the instance, such as <code>/dev/sdh</code>. For the root device, you can use the explicit device name or you can set this parameter to <code>ROOT_DEVICE</code> and OpsWorks Stacks will provide the correct device name.</p>
    pub fn device_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device name that is exposed to the instance, such as <code>/dev/sdh</code>. For the root device, you can use the explicit device name or you can set this parameter to <code>ROOT_DEVICE</code> and OpsWorks Stacks will provide the correct device name.</p>
    pub fn set_device_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_name = input;
        self
    }
    /// <p>The device name that is exposed to the instance, such as <code>/dev/sdh</code>. For the root device, you can use the explicit device name or you can set this parameter to <code>ROOT_DEVICE</code> and OpsWorks Stacks will provide the correct device name.</p>
    pub fn get_device_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_name
    }
    /// <p>Suppresses the specified device included in the AMI's block device mapping.</p>
    pub fn no_device(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.no_device = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Suppresses the specified device included in the AMI's block device mapping.</p>
    pub fn set_no_device(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.no_device = input;
        self
    }
    /// <p>Suppresses the specified device included in the AMI's block device mapping.</p>
    pub fn get_no_device(&self) -> &::std::option::Option<::std::string::String> {
        &self.no_device
    }
    /// <p>The virtual device name. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a>.</p>
    pub fn virtual_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The virtual device name. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a>.</p>
    pub fn set_virtual_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_name = input;
        self
    }
    /// <p>The virtual device name. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html">BlockDeviceMapping</a>.</p>
    pub fn get_virtual_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_name
    }
    /// <p>An <code>EBSBlockDevice</code> that defines how to configure an Amazon EBS volume when the instance is launched.</p>
    pub fn ebs(mut self, input: crate::types::EbsBlockDevice) -> Self {
        self.ebs = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <code>EBSBlockDevice</code> that defines how to configure an Amazon EBS volume when the instance is launched.</p>
    pub fn set_ebs(mut self, input: ::std::option::Option<crate::types::EbsBlockDevice>) -> Self {
        self.ebs = input;
        self
    }
    /// <p>An <code>EBSBlockDevice</code> that defines how to configure an Amazon EBS volume when the instance is launched.</p>
    pub fn get_ebs(&self) -> &::std::option::Option<crate::types::EbsBlockDevice> {
        &self.ebs
    }
    /// Consumes the builder and constructs a [`BlockDeviceMapping`](crate::types::BlockDeviceMapping).
    pub fn build(self) -> crate::types::BlockDeviceMapping {
        crate::types::BlockDeviceMapping {
            device_name: self.device_name,
            no_device: self.no_device,
            virtual_name: self.virtual_name,
            ebs: self.ebs,
        }
    }
}
