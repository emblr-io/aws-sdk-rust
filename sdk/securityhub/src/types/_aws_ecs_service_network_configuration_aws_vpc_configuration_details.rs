// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>For tasks that use the <code>awsvpc</code> networking mode, the VPC subnet and security group configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails {
    /// <p>Whether the task's elastic network interface receives a public IP address. The default value is <code>DISABLED</code>.</p>
    /// <p>Valid values: <code>ENABLED</code> | <code>DISABLED</code></p>
    pub assign_public_ip: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of the security groups associated with the task or service.</p>
    /// <p>You can provide up to five security groups.</p>
    pub security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The IDs of the subnets associated with the task or service.</p>
    /// <p>You can provide up to 16 subnets.</p>
    pub subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails {
    /// <p>Whether the task's elastic network interface receives a public IP address. The default value is <code>DISABLED</code>.</p>
    /// <p>Valid values: <code>ENABLED</code> | <code>DISABLED</code></p>
    pub fn assign_public_ip(&self) -> ::std::option::Option<&str> {
        self.assign_public_ip.as_deref()
    }
    /// <p>The IDs of the security groups associated with the task or service.</p>
    /// <p>You can provide up to five security groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_groups.is_none()`.
    pub fn security_groups(&self) -> &[::std::string::String] {
        self.security_groups.as_deref().unwrap_or_default()
    }
    /// <p>The IDs of the subnets associated with the task or service.</p>
    /// <p>You can provide up to 16 subnets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnets.is_none()`.
    pub fn subnets(&self) -> &[::std::string::String] {
        self.subnets.as_deref().unwrap_or_default()
    }
}
impl AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails`](crate::types::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails).
    pub fn builder() -> crate::types::builders::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetailsBuilder {
        crate::types::builders::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails`](crate::types::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetailsBuilder {
    pub(crate) assign_public_ip: ::std::option::Option<::std::string::String>,
    pub(crate) security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetailsBuilder {
    /// <p>Whether the task's elastic network interface receives a public IP address. The default value is <code>DISABLED</code>.</p>
    /// <p>Valid values: <code>ENABLED</code> | <code>DISABLED</code></p>
    pub fn assign_public_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assign_public_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Whether the task's elastic network interface receives a public IP address. The default value is <code>DISABLED</code>.</p>
    /// <p>Valid values: <code>ENABLED</code> | <code>DISABLED</code></p>
    pub fn set_assign_public_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assign_public_ip = input;
        self
    }
    /// <p>Whether the task's elastic network interface receives a public IP address. The default value is <code>DISABLED</code>.</p>
    /// <p>Valid values: <code>ENABLED</code> | <code>DISABLED</code></p>
    pub fn get_assign_public_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.assign_public_ip
    }
    /// Appends an item to `security_groups`.
    ///
    /// To override the contents of this collection use [`set_security_groups`](Self::set_security_groups).
    ///
    /// <p>The IDs of the security groups associated with the task or service.</p>
    /// <p>You can provide up to five security groups.</p>
    pub fn security_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_groups.unwrap_or_default();
        v.push(input.into());
        self.security_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the security groups associated with the task or service.</p>
    /// <p>You can provide up to five security groups.</p>
    pub fn set_security_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_groups = input;
        self
    }
    /// <p>The IDs of the security groups associated with the task or service.</p>
    /// <p>You can provide up to five security groups.</p>
    pub fn get_security_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_groups
    }
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>The IDs of the subnets associated with the task or service.</p>
    /// <p>You can provide up to 16 subnets.</p>
    pub fn subnets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input.into());
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the subnets associated with the task or service.</p>
    /// <p>You can provide up to 16 subnets.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>The IDs of the subnets associated with the task or service.</p>
    /// <p>You can provide up to 16 subnets.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnets
    }
    /// Consumes the builder and constructs a [`AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails`](crate::types::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails).
    pub fn build(self) -> crate::types::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails {
        crate::types::AwsEcsServiceNetworkConfigurationAwsVpcConfigurationDetails {
            assign_public_ip: self.assign_public_ip,
            security_groups: self.security_groups,
            subnets: self.subnets,
        }
    }
}
