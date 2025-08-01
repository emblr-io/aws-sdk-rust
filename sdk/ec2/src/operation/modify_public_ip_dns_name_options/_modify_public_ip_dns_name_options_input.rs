// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyPublicIpDnsNameOptionsInput {
    /// <p>A network interface ID.</p>
    pub network_interface_id: ::std::option::Option<::std::string::String>,
    /// <p>The public hostname type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html">EC2 instance hostnames, DNS names, and domains</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <ul>
    /// <li>
    /// <p><code>public-dual-stack-dns-name</code>: A dual-stack public hostname for a network interface. Requests from within the VPC resolve to both the private IPv4 address and the IPv6 Global Unicast Address of the network interface. Requests from the internet resolve to both the public IPv4 and the IPv6 GUA address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv4-dns-name</code>: An IPv4-enabled public hostname for a network interface. Requests from within the VPC resolve to the private primary IPv4 address of the network interface. Requests from the internet resolve to the public IPv4 address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv6-dns-name</code>: An IPv6-enabled public hostname for a network interface. Requests from within the VPC or from the internet resolve to the IPv6 GUA of the network interface.</p></li>
    /// </ul>
    pub hostname_type: ::std::option::Option<crate::types::PublicIpDnsOption>,
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl ModifyPublicIpDnsNameOptionsInput {
    /// <p>A network interface ID.</p>
    pub fn network_interface_id(&self) -> ::std::option::Option<&str> {
        self.network_interface_id.as_deref()
    }
    /// <p>The public hostname type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html">EC2 instance hostnames, DNS names, and domains</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <ul>
    /// <li>
    /// <p><code>public-dual-stack-dns-name</code>: A dual-stack public hostname for a network interface. Requests from within the VPC resolve to both the private IPv4 address and the IPv6 Global Unicast Address of the network interface. Requests from the internet resolve to both the public IPv4 and the IPv6 GUA address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv4-dns-name</code>: An IPv4-enabled public hostname for a network interface. Requests from within the VPC resolve to the private primary IPv4 address of the network interface. Requests from the internet resolve to the public IPv4 address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv6-dns-name</code>: An IPv6-enabled public hostname for a network interface. Requests from within the VPC or from the internet resolve to the IPv6 GUA of the network interface.</p></li>
    /// </ul>
    pub fn hostname_type(&self) -> ::std::option::Option<&crate::types::PublicIpDnsOption> {
        self.hostname_type.as_ref()
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl ModifyPublicIpDnsNameOptionsInput {
    /// Creates a new builder-style object to manufacture [`ModifyPublicIpDnsNameOptionsInput`](crate::operation::modify_public_ip_dns_name_options::ModifyPublicIpDnsNameOptionsInput).
    pub fn builder() -> crate::operation::modify_public_ip_dns_name_options::builders::ModifyPublicIpDnsNameOptionsInputBuilder {
        crate::operation::modify_public_ip_dns_name_options::builders::ModifyPublicIpDnsNameOptionsInputBuilder::default()
    }
}

/// A builder for [`ModifyPublicIpDnsNameOptionsInput`](crate::operation::modify_public_ip_dns_name_options::ModifyPublicIpDnsNameOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyPublicIpDnsNameOptionsInputBuilder {
    pub(crate) network_interface_id: ::std::option::Option<::std::string::String>,
    pub(crate) hostname_type: ::std::option::Option<crate::types::PublicIpDnsOption>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl ModifyPublicIpDnsNameOptionsInputBuilder {
    /// <p>A network interface ID.</p>
    /// This field is required.
    pub fn network_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A network interface ID.</p>
    pub fn set_network_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_interface_id = input;
        self
    }
    /// <p>A network interface ID.</p>
    pub fn get_network_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_interface_id
    }
    /// <p>The public hostname type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html">EC2 instance hostnames, DNS names, and domains</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <ul>
    /// <li>
    /// <p><code>public-dual-stack-dns-name</code>: A dual-stack public hostname for a network interface. Requests from within the VPC resolve to both the private IPv4 address and the IPv6 Global Unicast Address of the network interface. Requests from the internet resolve to both the public IPv4 and the IPv6 GUA address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv4-dns-name</code>: An IPv4-enabled public hostname for a network interface. Requests from within the VPC resolve to the private primary IPv4 address of the network interface. Requests from the internet resolve to the public IPv4 address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv6-dns-name</code>: An IPv6-enabled public hostname for a network interface. Requests from within the VPC or from the internet resolve to the IPv6 GUA of the network interface.</p></li>
    /// </ul>
    /// This field is required.
    pub fn hostname_type(mut self, input: crate::types::PublicIpDnsOption) -> Self {
        self.hostname_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The public hostname type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html">EC2 instance hostnames, DNS names, and domains</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <ul>
    /// <li>
    /// <p><code>public-dual-stack-dns-name</code>: A dual-stack public hostname for a network interface. Requests from within the VPC resolve to both the private IPv4 address and the IPv6 Global Unicast Address of the network interface. Requests from the internet resolve to both the public IPv4 and the IPv6 GUA address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv4-dns-name</code>: An IPv4-enabled public hostname for a network interface. Requests from within the VPC resolve to the private primary IPv4 address of the network interface. Requests from the internet resolve to the public IPv4 address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv6-dns-name</code>: An IPv6-enabled public hostname for a network interface. Requests from within the VPC or from the internet resolve to the IPv6 GUA of the network interface.</p></li>
    /// </ul>
    pub fn set_hostname_type(mut self, input: ::std::option::Option<crate::types::PublicIpDnsOption>) -> Self {
        self.hostname_type = input;
        self
    }
    /// <p>The public hostname type. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html">EC2 instance hostnames, DNS names, and domains</a> in the <i>Amazon EC2 User Guide</i>.</p>
    /// <ul>
    /// <li>
    /// <p><code>public-dual-stack-dns-name</code>: A dual-stack public hostname for a network interface. Requests from within the VPC resolve to both the private IPv4 address and the IPv6 Global Unicast Address of the network interface. Requests from the internet resolve to both the public IPv4 and the IPv6 GUA address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv4-dns-name</code>: An IPv4-enabled public hostname for a network interface. Requests from within the VPC resolve to the private primary IPv4 address of the network interface. Requests from the internet resolve to the public IPv4 address of the network interface.</p></li>
    /// <li>
    /// <p><code>public-ipv6-dns-name</code>: An IPv6-enabled public hostname for a network interface. Requests from within the VPC or from the internet resolve to the IPv6 GUA of the network interface.</p></li>
    /// </ul>
    pub fn get_hostname_type(&self) -> &::std::option::Option<crate::types::PublicIpDnsOption> {
        &self.hostname_type
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`ModifyPublicIpDnsNameOptionsInput`](crate::operation::modify_public_ip_dns_name_options::ModifyPublicIpDnsNameOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_public_ip_dns_name_options::ModifyPublicIpDnsNameOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_public_ip_dns_name_options::ModifyPublicIpDnsNameOptionsInput {
            network_interface_id: self.network_interface_id,
            hostname_type: self.hostname_type,
            dry_run: self.dry_run,
        })
    }
}
