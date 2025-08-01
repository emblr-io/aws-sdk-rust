// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddIpRoutesInput {
    /// <p>Identifier (ID) of the directory to which to add the address block.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>IP address blocks, using CIDR format, of the traffic to route. This is often the IP address block of the DNS server used for your self-managed domain.</p>
    pub ip_routes: ::std::option::Option<::std::vec::Vec<crate::types::IpRoute>>,
    /// <p>If set to true, updates the inbound and outbound rules of the security group that has the description: "Amazon Web Services created security group for <i>directory ID</i> directory controllers." Following are the new rules:</p>
    /// <p>Inbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 123, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 138, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 135, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 636, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 1024-65535, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 3268-33269, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (UDP), Protocol: UDP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (TCP), Protocol: TCP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: LDAP, Protocol: TCP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: All ICMP, Protocol: All, Range: N/A, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// </ul>
    /// <p></p>
    /// <p>Outbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: All traffic, Protocol: All, Range: All, Destination: 0.0.0.0/0</p></li>
    /// </ul>
    /// <p>These security rules impact an internal network interface that is not exposed publicly.</p>
    pub update_security_group_for_directory_controllers: ::std::option::Option<bool>,
}
impl AddIpRoutesInput {
    /// <p>Identifier (ID) of the directory to which to add the address block.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>IP address blocks, using CIDR format, of the traffic to route. This is often the IP address block of the DNS server used for your self-managed domain.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ip_routes.is_none()`.
    pub fn ip_routes(&self) -> &[crate::types::IpRoute] {
        self.ip_routes.as_deref().unwrap_or_default()
    }
    /// <p>If set to true, updates the inbound and outbound rules of the security group that has the description: "Amazon Web Services created security group for <i>directory ID</i> directory controllers." Following are the new rules:</p>
    /// <p>Inbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 123, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 138, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 135, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 636, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 1024-65535, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 3268-33269, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (UDP), Protocol: UDP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (TCP), Protocol: TCP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: LDAP, Protocol: TCP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: All ICMP, Protocol: All, Range: N/A, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// </ul>
    /// <p></p>
    /// <p>Outbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: All traffic, Protocol: All, Range: All, Destination: 0.0.0.0/0</p></li>
    /// </ul>
    /// <p>These security rules impact an internal network interface that is not exposed publicly.</p>
    pub fn update_security_group_for_directory_controllers(&self) -> ::std::option::Option<bool> {
        self.update_security_group_for_directory_controllers
    }
}
impl AddIpRoutesInput {
    /// Creates a new builder-style object to manufacture [`AddIpRoutesInput`](crate::operation::add_ip_routes::AddIpRoutesInput).
    pub fn builder() -> crate::operation::add_ip_routes::builders::AddIpRoutesInputBuilder {
        crate::operation::add_ip_routes::builders::AddIpRoutesInputBuilder::default()
    }
}

/// A builder for [`AddIpRoutesInput`](crate::operation::add_ip_routes::AddIpRoutesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddIpRoutesInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) ip_routes: ::std::option::Option<::std::vec::Vec<crate::types::IpRoute>>,
    pub(crate) update_security_group_for_directory_controllers: ::std::option::Option<bool>,
}
impl AddIpRoutesInputBuilder {
    /// <p>Identifier (ID) of the directory to which to add the address block.</p>
    /// This field is required.
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier (ID) of the directory to which to add the address block.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>Identifier (ID) of the directory to which to add the address block.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// Appends an item to `ip_routes`.
    ///
    /// To override the contents of this collection use [`set_ip_routes`](Self::set_ip_routes).
    ///
    /// <p>IP address blocks, using CIDR format, of the traffic to route. This is often the IP address block of the DNS server used for your self-managed domain.</p>
    pub fn ip_routes(mut self, input: crate::types::IpRoute) -> Self {
        let mut v = self.ip_routes.unwrap_or_default();
        v.push(input);
        self.ip_routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>IP address blocks, using CIDR format, of the traffic to route. This is often the IP address block of the DNS server used for your self-managed domain.</p>
    pub fn set_ip_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IpRoute>>) -> Self {
        self.ip_routes = input;
        self
    }
    /// <p>IP address blocks, using CIDR format, of the traffic to route. This is often the IP address block of the DNS server used for your self-managed domain.</p>
    pub fn get_ip_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IpRoute>> {
        &self.ip_routes
    }
    /// <p>If set to true, updates the inbound and outbound rules of the security group that has the description: "Amazon Web Services created security group for <i>directory ID</i> directory controllers." Following are the new rules:</p>
    /// <p>Inbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 123, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 138, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 135, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 636, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 1024-65535, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 3268-33269, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (UDP), Protocol: UDP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (TCP), Protocol: TCP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: LDAP, Protocol: TCP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: All ICMP, Protocol: All, Range: N/A, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// </ul>
    /// <p></p>
    /// <p>Outbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: All traffic, Protocol: All, Range: All, Destination: 0.0.0.0/0</p></li>
    /// </ul>
    /// <p>These security rules impact an internal network interface that is not exposed publicly.</p>
    pub fn update_security_group_for_directory_controllers(mut self, input: bool) -> Self {
        self.update_security_group_for_directory_controllers = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true, updates the inbound and outbound rules of the security group that has the description: "Amazon Web Services created security group for <i>directory ID</i> directory controllers." Following are the new rules:</p>
    /// <p>Inbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 123, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 138, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 135, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 636, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 1024-65535, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 3268-33269, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (UDP), Protocol: UDP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (TCP), Protocol: TCP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: LDAP, Protocol: TCP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: All ICMP, Protocol: All, Range: N/A, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// </ul>
    /// <p></p>
    /// <p>Outbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: All traffic, Protocol: All, Range: All, Destination: 0.0.0.0/0</p></li>
    /// </ul>
    /// <p>These security rules impact an internal network interface that is not exposed publicly.</p>
    pub fn set_update_security_group_for_directory_controllers(mut self, input: ::std::option::Option<bool>) -> Self {
        self.update_security_group_for_directory_controllers = input;
        self
    }
    /// <p>If set to true, updates the inbound and outbound rules of the security group that has the description: "Amazon Web Services created security group for <i>directory ID</i> directory controllers." Following are the new rules:</p>
    /// <p>Inbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 123, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 138, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom UDP Rule, Protocol: UDP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 88, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 135, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 445, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 464, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 636, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 1024-65535, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: Custom TCP Rule, Protocol: TCP, Range: 3268-33269, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (UDP), Protocol: UDP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: DNS (TCP), Protocol: TCP, Range: 53, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: LDAP, Protocol: TCP, Range: 389, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// <li>
    /// <p>Type: All ICMP, Protocol: All, Range: N/A, Source: Managed Microsoft AD VPC IPv4 CIDR</p></li>
    /// </ul>
    /// <p></p>
    /// <p>Outbound:</p>
    /// <ul>
    /// <li>
    /// <p>Type: All traffic, Protocol: All, Range: All, Destination: 0.0.0.0/0</p></li>
    /// </ul>
    /// <p>These security rules impact an internal network interface that is not exposed publicly.</p>
    pub fn get_update_security_group_for_directory_controllers(&self) -> &::std::option::Option<bool> {
        &self.update_security_group_for_directory_controllers
    }
    /// Consumes the builder and constructs a [`AddIpRoutesInput`](crate::operation::add_ip_routes::AddIpRoutesInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::add_ip_routes::AddIpRoutesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::add_ip_routes::AddIpRoutesInput {
            directory_id: self.directory_id,
            ip_routes: self.ip_routes,
            update_security_group_for_directory_controllers: self.update_security_group_for_directory_controllers,
        })
    }
}
