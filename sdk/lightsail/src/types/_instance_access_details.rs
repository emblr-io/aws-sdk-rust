// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for gaining temporary access to one of your Amazon Lightsail instances.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceAccessDetails {
    /// <p>For SSH access, the public key to use when accessing your instance For OpenSSH clients (command line SSH), you should save this value to <code>tempkey-cert.pub</code>.</p>
    pub cert_key: ::std::option::Option<::std::string::String>,
    /// <p>For SSH access, the date on which the temporary keys expire.</p>
    pub expires_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The public IP address of the Amazon Lightsail instance.</p>
    pub ip_address: ::std::option::Option<::std::string::String>,
    /// <p>The IPv6 address of the Amazon Lightsail instance.</p>
    pub ipv6_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>For RDP access, the password for your Amazon Lightsail instance. Password will be an empty string if the password for your new instance is not ready yet. When you create an instance, it can take up to 15 minutes for the instance to be ready.</p><note>
    /// <p>If you create an instance using any key pair other than the default (<code>LightsailDefaultKeyPair</code>), <code>password</code> will always be an empty string.</p>
    /// <p>If you change the Administrator password on the instance, Lightsail will continue to return the original password value. When accessing the instance using RDP, you need to manually enter the Administrator password after changing it from the default.</p>
    /// </note>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>For a Windows Server-based instance, an object with the data you can use to retrieve your password. This is only needed if <code>password</code> is empty and the instance is not new (and therefore the password is not ready yet). When you create an instance, it can take up to 15 minutes for the instance to be ready.</p>
    pub password_data: ::std::option::Option<crate::types::PasswordData>,
    /// <p>For SSH access, the temporary private key. For OpenSSH clients (command line SSH), you should save this value to <code>tempkey</code>).</p>
    pub private_key: ::std::option::Option<::std::string::String>,
    /// <p>The protocol for these Amazon Lightsail instance access details.</p>
    pub protocol: ::std::option::Option<crate::types::InstanceAccessProtocol>,
    /// <p>The name of this Amazon Lightsail instance.</p>
    pub instance_name: ::std::option::Option<::std::string::String>,
    /// <p>The user name to use when logging in to the Amazon Lightsail instance.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>Describes the public SSH host keys or the RDP certificate.</p>
    pub host_keys: ::std::option::Option<::std::vec::Vec<crate::types::HostKeyAttributes>>,
}
impl InstanceAccessDetails {
    /// <p>For SSH access, the public key to use when accessing your instance For OpenSSH clients (command line SSH), you should save this value to <code>tempkey-cert.pub</code>.</p>
    pub fn cert_key(&self) -> ::std::option::Option<&str> {
        self.cert_key.as_deref()
    }
    /// <p>For SSH access, the date on which the temporary keys expire.</p>
    pub fn expires_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.expires_at.as_ref()
    }
    /// <p>The public IP address of the Amazon Lightsail instance.</p>
    pub fn ip_address(&self) -> ::std::option::Option<&str> {
        self.ip_address.as_deref()
    }
    /// <p>The IPv6 address of the Amazon Lightsail instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ipv6_addresses.is_none()`.
    pub fn ipv6_addresses(&self) -> &[::std::string::String] {
        self.ipv6_addresses.as_deref().unwrap_or_default()
    }
    /// <p>For RDP access, the password for your Amazon Lightsail instance. Password will be an empty string if the password for your new instance is not ready yet. When you create an instance, it can take up to 15 minutes for the instance to be ready.</p><note>
    /// <p>If you create an instance using any key pair other than the default (<code>LightsailDefaultKeyPair</code>), <code>password</code> will always be an empty string.</p>
    /// <p>If you change the Administrator password on the instance, Lightsail will continue to return the original password value. When accessing the instance using RDP, you need to manually enter the Administrator password after changing it from the default.</p>
    /// </note>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>For a Windows Server-based instance, an object with the data you can use to retrieve your password. This is only needed if <code>password</code> is empty and the instance is not new (and therefore the password is not ready yet). When you create an instance, it can take up to 15 minutes for the instance to be ready.</p>
    pub fn password_data(&self) -> ::std::option::Option<&crate::types::PasswordData> {
        self.password_data.as_ref()
    }
    /// <p>For SSH access, the temporary private key. For OpenSSH clients (command line SSH), you should save this value to <code>tempkey</code>).</p>
    pub fn private_key(&self) -> ::std::option::Option<&str> {
        self.private_key.as_deref()
    }
    /// <p>The protocol for these Amazon Lightsail instance access details.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::InstanceAccessProtocol> {
        self.protocol.as_ref()
    }
    /// <p>The name of this Amazon Lightsail instance.</p>
    pub fn instance_name(&self) -> ::std::option::Option<&str> {
        self.instance_name.as_deref()
    }
    /// <p>The user name to use when logging in to the Amazon Lightsail instance.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>Describes the public SSH host keys or the RDP certificate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.host_keys.is_none()`.
    pub fn host_keys(&self) -> &[crate::types::HostKeyAttributes] {
        self.host_keys.as_deref().unwrap_or_default()
    }
}
impl InstanceAccessDetails {
    /// Creates a new builder-style object to manufacture [`InstanceAccessDetails`](crate::types::InstanceAccessDetails).
    pub fn builder() -> crate::types::builders::InstanceAccessDetailsBuilder {
        crate::types::builders::InstanceAccessDetailsBuilder::default()
    }
}

/// A builder for [`InstanceAccessDetails`](crate::types::InstanceAccessDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceAccessDetailsBuilder {
    pub(crate) cert_key: ::std::option::Option<::std::string::String>,
    pub(crate) expires_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) ipv6_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) password_data: ::std::option::Option<crate::types::PasswordData>,
    pub(crate) private_key: ::std::option::Option<::std::string::String>,
    pub(crate) protocol: ::std::option::Option<crate::types::InstanceAccessProtocol>,
    pub(crate) instance_name: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) host_keys: ::std::option::Option<::std::vec::Vec<crate::types::HostKeyAttributes>>,
}
impl InstanceAccessDetailsBuilder {
    /// <p>For SSH access, the public key to use when accessing your instance For OpenSSH clients (command line SSH), you should save this value to <code>tempkey-cert.pub</code>.</p>
    pub fn cert_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cert_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For SSH access, the public key to use when accessing your instance For OpenSSH clients (command line SSH), you should save this value to <code>tempkey-cert.pub</code>.</p>
    pub fn set_cert_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cert_key = input;
        self
    }
    /// <p>For SSH access, the public key to use when accessing your instance For OpenSSH clients (command line SSH), you should save this value to <code>tempkey-cert.pub</code>.</p>
    pub fn get_cert_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.cert_key
    }
    /// <p>For SSH access, the date on which the temporary keys expire.</p>
    pub fn expires_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.expires_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>For SSH access, the date on which the temporary keys expire.</p>
    pub fn set_expires_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.expires_at = input;
        self
    }
    /// <p>For SSH access, the date on which the temporary keys expire.</p>
    pub fn get_expires_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.expires_at
    }
    /// <p>The public IP address of the Amazon Lightsail instance.</p>
    pub fn ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The public IP address of the Amazon Lightsail instance.</p>
    pub fn set_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ip_address = input;
        self
    }
    /// <p>The public IP address of the Amazon Lightsail instance.</p>
    pub fn get_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.ip_address
    }
    /// Appends an item to `ipv6_addresses`.
    ///
    /// To override the contents of this collection use [`set_ipv6_addresses`](Self::set_ipv6_addresses).
    ///
    /// <p>The IPv6 address of the Amazon Lightsail instance.</p>
    pub fn ipv6_addresses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ipv6_addresses.unwrap_or_default();
        v.push(input.into());
        self.ipv6_addresses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IPv6 address of the Amazon Lightsail instance.</p>
    pub fn set_ipv6_addresses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ipv6_addresses = input;
        self
    }
    /// <p>The IPv6 address of the Amazon Lightsail instance.</p>
    pub fn get_ipv6_addresses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ipv6_addresses
    }
    /// <p>For RDP access, the password for your Amazon Lightsail instance. Password will be an empty string if the password for your new instance is not ready yet. When you create an instance, it can take up to 15 minutes for the instance to be ready.</p><note>
    /// <p>If you create an instance using any key pair other than the default (<code>LightsailDefaultKeyPair</code>), <code>password</code> will always be an empty string.</p>
    /// <p>If you change the Administrator password on the instance, Lightsail will continue to return the original password value. When accessing the instance using RDP, you need to manually enter the Administrator password after changing it from the default.</p>
    /// </note>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For RDP access, the password for your Amazon Lightsail instance. Password will be an empty string if the password for your new instance is not ready yet. When you create an instance, it can take up to 15 minutes for the instance to be ready.</p><note>
    /// <p>If you create an instance using any key pair other than the default (<code>LightsailDefaultKeyPair</code>), <code>password</code> will always be an empty string.</p>
    /// <p>If you change the Administrator password on the instance, Lightsail will continue to return the original password value. When accessing the instance using RDP, you need to manually enter the Administrator password after changing it from the default.</p>
    /// </note>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>For RDP access, the password for your Amazon Lightsail instance. Password will be an empty string if the password for your new instance is not ready yet. When you create an instance, it can take up to 15 minutes for the instance to be ready.</p><note>
    /// <p>If you create an instance using any key pair other than the default (<code>LightsailDefaultKeyPair</code>), <code>password</code> will always be an empty string.</p>
    /// <p>If you change the Administrator password on the instance, Lightsail will continue to return the original password value. When accessing the instance using RDP, you need to manually enter the Administrator password after changing it from the default.</p>
    /// </note>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// <p>For a Windows Server-based instance, an object with the data you can use to retrieve your password. This is only needed if <code>password</code> is empty and the instance is not new (and therefore the password is not ready yet). When you create an instance, it can take up to 15 minutes for the instance to be ready.</p>
    pub fn password_data(mut self, input: crate::types::PasswordData) -> Self {
        self.password_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a Windows Server-based instance, an object with the data you can use to retrieve your password. This is only needed if <code>password</code> is empty and the instance is not new (and therefore the password is not ready yet). When you create an instance, it can take up to 15 minutes for the instance to be ready.</p>
    pub fn set_password_data(mut self, input: ::std::option::Option<crate::types::PasswordData>) -> Self {
        self.password_data = input;
        self
    }
    /// <p>For a Windows Server-based instance, an object with the data you can use to retrieve your password. This is only needed if <code>password</code> is empty and the instance is not new (and therefore the password is not ready yet). When you create an instance, it can take up to 15 minutes for the instance to be ready.</p>
    pub fn get_password_data(&self) -> &::std::option::Option<crate::types::PasswordData> {
        &self.password_data
    }
    /// <p>For SSH access, the temporary private key. For OpenSSH clients (command line SSH), you should save this value to <code>tempkey</code>).</p>
    pub fn private_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.private_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For SSH access, the temporary private key. For OpenSSH clients (command line SSH), you should save this value to <code>tempkey</code>).</p>
    pub fn set_private_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.private_key = input;
        self
    }
    /// <p>For SSH access, the temporary private key. For OpenSSH clients (command line SSH), you should save this value to <code>tempkey</code>).</p>
    pub fn get_private_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.private_key
    }
    /// <p>The protocol for these Amazon Lightsail instance access details.</p>
    pub fn protocol(mut self, input: crate::types::InstanceAccessProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protocol for these Amazon Lightsail instance access details.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::InstanceAccessProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The protocol for these Amazon Lightsail instance access details.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::InstanceAccessProtocol> {
        &self.protocol
    }
    /// <p>The name of this Amazon Lightsail instance.</p>
    pub fn instance_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this Amazon Lightsail instance.</p>
    pub fn set_instance_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_name = input;
        self
    }
    /// <p>The name of this Amazon Lightsail instance.</p>
    pub fn get_instance_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_name
    }
    /// <p>The user name to use when logging in to the Amazon Lightsail instance.</p>
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user name to use when logging in to the Amazon Lightsail instance.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The user name to use when logging in to the Amazon Lightsail instance.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// Appends an item to `host_keys`.
    ///
    /// To override the contents of this collection use [`set_host_keys`](Self::set_host_keys).
    ///
    /// <p>Describes the public SSH host keys or the RDP certificate.</p>
    pub fn host_keys(mut self, input: crate::types::HostKeyAttributes) -> Self {
        let mut v = self.host_keys.unwrap_or_default();
        v.push(input);
        self.host_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the public SSH host keys or the RDP certificate.</p>
    pub fn set_host_keys(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::HostKeyAttributes>>) -> Self {
        self.host_keys = input;
        self
    }
    /// <p>Describes the public SSH host keys or the RDP certificate.</p>
    pub fn get_host_keys(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HostKeyAttributes>> {
        &self.host_keys
    }
    /// Consumes the builder and constructs a [`InstanceAccessDetails`](crate::types::InstanceAccessDetails).
    pub fn build(self) -> crate::types::InstanceAccessDetails {
        crate::types::InstanceAccessDetails {
            cert_key: self.cert_key,
            expires_at: self.expires_at,
            ip_address: self.ip_address,
            ipv6_addresses: self.ipv6_addresses,
            password: self.password,
            password_data: self.password_data,
            private_key: self.private_key,
            protocol: self.protocol,
            instance_name: self.instance_name,
            username: self.username,
            host_keys: self.host_keys,
        }
    }
}
