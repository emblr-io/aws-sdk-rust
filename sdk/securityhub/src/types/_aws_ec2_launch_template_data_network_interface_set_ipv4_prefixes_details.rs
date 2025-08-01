// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details on one or more IPv4 prefixes for a network interface.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails {
    /// <p>The IPv4 prefix. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html">Assigning prefixes to Amazon EC2 network interfaces</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub ipv4_prefix: ::std::option::Option<::std::string::String>,
}
impl AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails {
    /// <p>The IPv4 prefix. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html">Assigning prefixes to Amazon EC2 network interfaces</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn ipv4_prefix(&self) -> ::std::option::Option<&str> {
        self.ipv4_prefix.as_deref()
    }
}
impl AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails`](crate::types::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails).
    pub fn builder() -> crate::types::builders::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetailsBuilder {
        crate::types::builders::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails`](crate::types::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetailsBuilder {
    pub(crate) ipv4_prefix: ::std::option::Option<::std::string::String>,
}
impl AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetailsBuilder {
    /// <p>The IPv4 prefix. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html">Assigning prefixes to Amazon EC2 network interfaces</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn ipv4_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ipv4_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IPv4 prefix. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html">Assigning prefixes to Amazon EC2 network interfaces</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn set_ipv4_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ipv4_prefix = input;
        self
    }
    /// <p>The IPv4 prefix. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-prefix-eni.html">Assigning prefixes to Amazon EC2 network interfaces</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn get_ipv4_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.ipv4_prefix
    }
    /// Consumes the builder and constructs a [`AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails`](crate::types::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails).
    pub fn build(self) -> crate::types::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails {
        crate::types::AwsEc2LaunchTemplateDataNetworkInterfaceSetIpv4PrefixesDetails {
            ipv4_prefix: self.ipv4_prefix,
        }
    }
}
