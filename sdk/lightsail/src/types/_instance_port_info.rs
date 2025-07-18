// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes information about ports for an Amazon Lightsail instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstancePortInfo {
    /// <p>The first port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP type for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP type for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub from_port: i32,
    /// <p>The last port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP code for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP code for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub to_port: i32,
    /// <p>The IP protocol name.</p>
    /// <p>The name can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>tcp</code> - Transmission Control Protocol (TCP) provides reliable, ordered, and error-checked delivery of streamed data between applications running on hosts communicating by an IP network. If you have an application that doesn't require reliable data stream service, use UDP instead.</p></li>
    /// <li>
    /// <p><code>all</code> - All transport layer protocol types. For more general information, see <a href="https://en.wikipedia.org/wiki/Transport_layer">Transport layer</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p><code>udp</code> - With User Datagram Protocol (UDP), computer applications can send messages (or datagrams) to other hosts on an Internet Protocol (IP) network. Prior communications are not required to set up transmission channels or data paths. Applications that don't require reliable data stream service can use UDP, which provides a connectionless datagram service that emphasizes reduced latency over reliability. If you do require reliable data stream service, use TCP instead.</p></li>
    /// <li>
    /// <p><code>icmp</code> - Internet Control Message Protocol (ICMP) is used to send error messages and operational information indicating success or failure when communicating with an instance. For example, an error is indicated when an instance could not be reached. When you specify <code>icmp</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// <li>
    /// <p><code>icmp6</code> - Internet Control Message Protocol (ICMP) for IPv6. When you specify <code>icmp6</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// </ul>
    pub protocol: ::std::option::Option<crate::types::NetworkProtocol>,
    /// <p>The location from which access is allowed. For example, <code>Anywhere (0.0.0.0/0)</code>, or <code>Custom</code> if a specific IP address or range of IP addresses is allowed.</p>
    pub access_from: ::std::option::Option<::std::string::String>,
    /// <p>The type of access (<code>Public</code> or <code>Private</code>).</p>
    pub access_type: ::std::option::Option<crate::types::PortAccessType>,
    /// <p>The common name of the port information.</p>
    pub common_name: ::std::option::Option<::std::string::String>,
    /// <p>The access direction (<code>inbound</code> or <code>outbound</code>).</p><note>
    /// <p>Lightsail currently supports only <code>inbound</code> access direction.</p>
    /// </note>
    pub access_direction: ::std::option::Option<crate::types::AccessDirection>,
    /// <p>The IPv4 address, or range of IPv4 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol.</p><note>
    /// <p>The <code>ipv6Cidrs</code> parameter lists the IPv6 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub cidrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The IPv6 address, or range of IPv6 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol. Only devices with an IPv6 address can connect to an instance through IPv6; otherwise, IPv4 should be used.</p><note>
    /// <p>The <code>cidrs</code> parameter lists the IPv4 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub ipv6_cidrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An alias that defines access for a preconfigured range of IP addresses.</p>
    /// <p>The only alias currently supported is <code>lightsail-connect</code>, which allows IP addresses of the browser-based RDP/SSH client in the Lightsail console to connect to your instance.</p>
    pub cidr_list_aliases: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl InstancePortInfo {
    /// <p>The first port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP type for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP type for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn from_port(&self) -> i32 {
        self.from_port
    }
    /// <p>The last port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP code for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP code for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn to_port(&self) -> i32 {
        self.to_port
    }
    /// <p>The IP protocol name.</p>
    /// <p>The name can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>tcp</code> - Transmission Control Protocol (TCP) provides reliable, ordered, and error-checked delivery of streamed data between applications running on hosts communicating by an IP network. If you have an application that doesn't require reliable data stream service, use UDP instead.</p></li>
    /// <li>
    /// <p><code>all</code> - All transport layer protocol types. For more general information, see <a href="https://en.wikipedia.org/wiki/Transport_layer">Transport layer</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p><code>udp</code> - With User Datagram Protocol (UDP), computer applications can send messages (or datagrams) to other hosts on an Internet Protocol (IP) network. Prior communications are not required to set up transmission channels or data paths. Applications that don't require reliable data stream service can use UDP, which provides a connectionless datagram service that emphasizes reduced latency over reliability. If you do require reliable data stream service, use TCP instead.</p></li>
    /// <li>
    /// <p><code>icmp</code> - Internet Control Message Protocol (ICMP) is used to send error messages and operational information indicating success or failure when communicating with an instance. For example, an error is indicated when an instance could not be reached. When you specify <code>icmp</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// <li>
    /// <p><code>icmp6</code> - Internet Control Message Protocol (ICMP) for IPv6. When you specify <code>icmp6</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// </ul>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::NetworkProtocol> {
        self.protocol.as_ref()
    }
    /// <p>The location from which access is allowed. For example, <code>Anywhere (0.0.0.0/0)</code>, or <code>Custom</code> if a specific IP address or range of IP addresses is allowed.</p>
    pub fn access_from(&self) -> ::std::option::Option<&str> {
        self.access_from.as_deref()
    }
    /// <p>The type of access (<code>Public</code> or <code>Private</code>).</p>
    pub fn access_type(&self) -> ::std::option::Option<&crate::types::PortAccessType> {
        self.access_type.as_ref()
    }
    /// <p>The common name of the port information.</p>
    pub fn common_name(&self) -> ::std::option::Option<&str> {
        self.common_name.as_deref()
    }
    /// <p>The access direction (<code>inbound</code> or <code>outbound</code>).</p><note>
    /// <p>Lightsail currently supports only <code>inbound</code> access direction.</p>
    /// </note>
    pub fn access_direction(&self) -> ::std::option::Option<&crate::types::AccessDirection> {
        self.access_direction.as_ref()
    }
    /// <p>The IPv4 address, or range of IPv4 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol.</p><note>
    /// <p>The <code>ipv6Cidrs</code> parameter lists the IPv6 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cidrs.is_none()`.
    pub fn cidrs(&self) -> &[::std::string::String] {
        self.cidrs.as_deref().unwrap_or_default()
    }
    /// <p>The IPv6 address, or range of IPv6 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol. Only devices with an IPv6 address can connect to an instance through IPv6; otherwise, IPv4 should be used.</p><note>
    /// <p>The <code>cidrs</code> parameter lists the IPv4 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ipv6_cidrs.is_none()`.
    pub fn ipv6_cidrs(&self) -> &[::std::string::String] {
        self.ipv6_cidrs.as_deref().unwrap_or_default()
    }
    /// <p>An alias that defines access for a preconfigured range of IP addresses.</p>
    /// <p>The only alias currently supported is <code>lightsail-connect</code>, which allows IP addresses of the browser-based RDP/SSH client in the Lightsail console to connect to your instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cidr_list_aliases.is_none()`.
    pub fn cidr_list_aliases(&self) -> &[::std::string::String] {
        self.cidr_list_aliases.as_deref().unwrap_or_default()
    }
}
impl InstancePortInfo {
    /// Creates a new builder-style object to manufacture [`InstancePortInfo`](crate::types::InstancePortInfo).
    pub fn builder() -> crate::types::builders::InstancePortInfoBuilder {
        crate::types::builders::InstancePortInfoBuilder::default()
    }
}

/// A builder for [`InstancePortInfo`](crate::types::InstancePortInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstancePortInfoBuilder {
    pub(crate) from_port: ::std::option::Option<i32>,
    pub(crate) to_port: ::std::option::Option<i32>,
    pub(crate) protocol: ::std::option::Option<crate::types::NetworkProtocol>,
    pub(crate) access_from: ::std::option::Option<::std::string::String>,
    pub(crate) access_type: ::std::option::Option<crate::types::PortAccessType>,
    pub(crate) common_name: ::std::option::Option<::std::string::String>,
    pub(crate) access_direction: ::std::option::Option<crate::types::AccessDirection>,
    pub(crate) cidrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) ipv6_cidrs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) cidr_list_aliases: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl InstancePortInfoBuilder {
    /// <p>The first port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP type for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP type for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn from_port(mut self, input: i32) -> Self {
        self.from_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The first port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP type for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP type for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn set_from_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.from_port = input;
        self
    }
    /// <p>The first port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP type for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP type for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn get_from_port(&self) -> &::std::option::Option<i32> {
        &self.from_port
    }
    /// <p>The last port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP code for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP code for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn to_port(mut self, input: i32) -> Self {
        self.to_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP code for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP code for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn set_to_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.to_port = input;
        self
    }
    /// <p>The last port in a range of open ports on an instance.</p>
    /// <p>Allowed ports:</p>
    /// <ul>
    /// <li>
    /// <p>TCP and UDP - <code>0</code> to <code>65535</code></p></li>
    /// <li>
    /// <p>ICMP - The ICMP code for IPv4 addresses. For example, specify <code>8</code> as the <code>fromPort</code> (ICMP type), and <code>-1</code> as the <code>toPort</code> (ICMP code), to enable ICMP Ping. For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages">Control Messages</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p>ICMPv6 - The ICMP code for IPv6 addresses. For example, specify <code>128</code> as the <code>fromPort</code> (ICMPv6 type), and <code>0</code> as <code>toPort</code> (ICMPv6 code). For more information, see <a href="https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6">Internet Control Message Protocol for IPv6</a>.</p></li>
    /// </ul>
    pub fn get_to_port(&self) -> &::std::option::Option<i32> {
        &self.to_port
    }
    /// <p>The IP protocol name.</p>
    /// <p>The name can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>tcp</code> - Transmission Control Protocol (TCP) provides reliable, ordered, and error-checked delivery of streamed data between applications running on hosts communicating by an IP network. If you have an application that doesn't require reliable data stream service, use UDP instead.</p></li>
    /// <li>
    /// <p><code>all</code> - All transport layer protocol types. For more general information, see <a href="https://en.wikipedia.org/wiki/Transport_layer">Transport layer</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p><code>udp</code> - With User Datagram Protocol (UDP), computer applications can send messages (or datagrams) to other hosts on an Internet Protocol (IP) network. Prior communications are not required to set up transmission channels or data paths. Applications that don't require reliable data stream service can use UDP, which provides a connectionless datagram service that emphasizes reduced latency over reliability. If you do require reliable data stream service, use TCP instead.</p></li>
    /// <li>
    /// <p><code>icmp</code> - Internet Control Message Protocol (ICMP) is used to send error messages and operational information indicating success or failure when communicating with an instance. For example, an error is indicated when an instance could not be reached. When you specify <code>icmp</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// <li>
    /// <p><code>icmp6</code> - Internet Control Message Protocol (ICMP) for IPv6. When you specify <code>icmp6</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// </ul>
    pub fn protocol(mut self, input: crate::types::NetworkProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IP protocol name.</p>
    /// <p>The name can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>tcp</code> - Transmission Control Protocol (TCP) provides reliable, ordered, and error-checked delivery of streamed data between applications running on hosts communicating by an IP network. If you have an application that doesn't require reliable data stream service, use UDP instead.</p></li>
    /// <li>
    /// <p><code>all</code> - All transport layer protocol types. For more general information, see <a href="https://en.wikipedia.org/wiki/Transport_layer">Transport layer</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p><code>udp</code> - With User Datagram Protocol (UDP), computer applications can send messages (or datagrams) to other hosts on an Internet Protocol (IP) network. Prior communications are not required to set up transmission channels or data paths. Applications that don't require reliable data stream service can use UDP, which provides a connectionless datagram service that emphasizes reduced latency over reliability. If you do require reliable data stream service, use TCP instead.</p></li>
    /// <li>
    /// <p><code>icmp</code> - Internet Control Message Protocol (ICMP) is used to send error messages and operational information indicating success or failure when communicating with an instance. For example, an error is indicated when an instance could not be reached. When you specify <code>icmp</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// <li>
    /// <p><code>icmp6</code> - Internet Control Message Protocol (ICMP) for IPv6. When you specify <code>icmp6</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// </ul>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::NetworkProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The IP protocol name.</p>
    /// <p>The name can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>tcp</code> - Transmission Control Protocol (TCP) provides reliable, ordered, and error-checked delivery of streamed data between applications running on hosts communicating by an IP network. If you have an application that doesn't require reliable data stream service, use UDP instead.</p></li>
    /// <li>
    /// <p><code>all</code> - All transport layer protocol types. For more general information, see <a href="https://en.wikipedia.org/wiki/Transport_layer">Transport layer</a> on <i>Wikipedia</i>.</p></li>
    /// <li>
    /// <p><code>udp</code> - With User Datagram Protocol (UDP), computer applications can send messages (or datagrams) to other hosts on an Internet Protocol (IP) network. Prior communications are not required to set up transmission channels or data paths. Applications that don't require reliable data stream service can use UDP, which provides a connectionless datagram service that emphasizes reduced latency over reliability. If you do require reliable data stream service, use TCP instead.</p></li>
    /// <li>
    /// <p><code>icmp</code> - Internet Control Message Protocol (ICMP) is used to send error messages and operational information indicating success or failure when communicating with an instance. For example, an error is indicated when an instance could not be reached. When you specify <code>icmp</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// <li>
    /// <p><code>icmp6</code> - Internet Control Message Protocol (ICMP) for IPv6. When you specify <code>icmp6</code> as the <code>protocol</code>, you must specify the ICMP type using the <code>fromPort</code> parameter, and ICMP code using the <code>toPort</code> parameter.</p></li>
    /// </ul>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::NetworkProtocol> {
        &self.protocol
    }
    /// <p>The location from which access is allowed. For example, <code>Anywhere (0.0.0.0/0)</code>, or <code>Custom</code> if a specific IP address or range of IP addresses is allowed.</p>
    pub fn access_from(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_from = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location from which access is allowed. For example, <code>Anywhere (0.0.0.0/0)</code>, or <code>Custom</code> if a specific IP address or range of IP addresses is allowed.</p>
    pub fn set_access_from(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_from = input;
        self
    }
    /// <p>The location from which access is allowed. For example, <code>Anywhere (0.0.0.0/0)</code>, or <code>Custom</code> if a specific IP address or range of IP addresses is allowed.</p>
    pub fn get_access_from(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_from
    }
    /// <p>The type of access (<code>Public</code> or <code>Private</code>).</p>
    pub fn access_type(mut self, input: crate::types::PortAccessType) -> Self {
        self.access_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of access (<code>Public</code> or <code>Private</code>).</p>
    pub fn set_access_type(mut self, input: ::std::option::Option<crate::types::PortAccessType>) -> Self {
        self.access_type = input;
        self
    }
    /// <p>The type of access (<code>Public</code> or <code>Private</code>).</p>
    pub fn get_access_type(&self) -> &::std::option::Option<crate::types::PortAccessType> {
        &self.access_type
    }
    /// <p>The common name of the port information.</p>
    pub fn common_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.common_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The common name of the port information.</p>
    pub fn set_common_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.common_name = input;
        self
    }
    /// <p>The common name of the port information.</p>
    pub fn get_common_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.common_name
    }
    /// <p>The access direction (<code>inbound</code> or <code>outbound</code>).</p><note>
    /// <p>Lightsail currently supports only <code>inbound</code> access direction.</p>
    /// </note>
    pub fn access_direction(mut self, input: crate::types::AccessDirection) -> Self {
        self.access_direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The access direction (<code>inbound</code> or <code>outbound</code>).</p><note>
    /// <p>Lightsail currently supports only <code>inbound</code> access direction.</p>
    /// </note>
    pub fn set_access_direction(mut self, input: ::std::option::Option<crate::types::AccessDirection>) -> Self {
        self.access_direction = input;
        self
    }
    /// <p>The access direction (<code>inbound</code> or <code>outbound</code>).</p><note>
    /// <p>Lightsail currently supports only <code>inbound</code> access direction.</p>
    /// </note>
    pub fn get_access_direction(&self) -> &::std::option::Option<crate::types::AccessDirection> {
        &self.access_direction
    }
    /// Appends an item to `cidrs`.
    ///
    /// To override the contents of this collection use [`set_cidrs`](Self::set_cidrs).
    ///
    /// <p>The IPv4 address, or range of IPv4 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol.</p><note>
    /// <p>The <code>ipv6Cidrs</code> parameter lists the IPv6 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn cidrs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.cidrs.unwrap_or_default();
        v.push(input.into());
        self.cidrs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IPv4 address, or range of IPv4 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol.</p><note>
    /// <p>The <code>ipv6Cidrs</code> parameter lists the IPv6 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn set_cidrs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.cidrs = input;
        self
    }
    /// <p>The IPv4 address, or range of IPv4 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol.</p><note>
    /// <p>The <code>ipv6Cidrs</code> parameter lists the IPv6 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn get_cidrs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.cidrs
    }
    /// Appends an item to `ipv6_cidrs`.
    ///
    /// To override the contents of this collection use [`set_ipv6_cidrs`](Self::set_ipv6_cidrs).
    ///
    /// <p>The IPv6 address, or range of IPv6 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol. Only devices with an IPv6 address can connect to an instance through IPv6; otherwise, IPv4 should be used.</p><note>
    /// <p>The <code>cidrs</code> parameter lists the IPv4 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn ipv6_cidrs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ipv6_cidrs.unwrap_or_default();
        v.push(input.into());
        self.ipv6_cidrs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IPv6 address, or range of IPv6 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol. Only devices with an IPv6 address can connect to an instance through IPv6; otherwise, IPv4 should be used.</p><note>
    /// <p>The <code>cidrs</code> parameter lists the IPv4 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn set_ipv6_cidrs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ipv6_cidrs = input;
        self
    }
    /// <p>The IPv6 address, or range of IPv6 addresses (in CIDR notation) that are allowed to connect to an instance through the ports, and the protocol. Only devices with an IPv6 address can connect to an instance through IPv6; otherwise, IPv4 should be used.</p><note>
    /// <p>The <code>cidrs</code> parameter lists the IPv4 addresses that are allowed to connect to an instance.</p>
    /// </note>
    /// <p>For more information about CIDR block notation, see <a href="https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation">Classless Inter-Domain Routing</a> on <i>Wikipedia</i>.</p>
    pub fn get_ipv6_cidrs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ipv6_cidrs
    }
    /// Appends an item to `cidr_list_aliases`.
    ///
    /// To override the contents of this collection use [`set_cidr_list_aliases`](Self::set_cidr_list_aliases).
    ///
    /// <p>An alias that defines access for a preconfigured range of IP addresses.</p>
    /// <p>The only alias currently supported is <code>lightsail-connect</code>, which allows IP addresses of the browser-based RDP/SSH client in the Lightsail console to connect to your instance.</p>
    pub fn cidr_list_aliases(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.cidr_list_aliases.unwrap_or_default();
        v.push(input.into());
        self.cidr_list_aliases = ::std::option::Option::Some(v);
        self
    }
    /// <p>An alias that defines access for a preconfigured range of IP addresses.</p>
    /// <p>The only alias currently supported is <code>lightsail-connect</code>, which allows IP addresses of the browser-based RDP/SSH client in the Lightsail console to connect to your instance.</p>
    pub fn set_cidr_list_aliases(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.cidr_list_aliases = input;
        self
    }
    /// <p>An alias that defines access for a preconfigured range of IP addresses.</p>
    /// <p>The only alias currently supported is <code>lightsail-connect</code>, which allows IP addresses of the browser-based RDP/SSH client in the Lightsail console to connect to your instance.</p>
    pub fn get_cidr_list_aliases(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.cidr_list_aliases
    }
    /// Consumes the builder and constructs a [`InstancePortInfo`](crate::types::InstancePortInfo).
    pub fn build(self) -> crate::types::InstancePortInfo {
        crate::types::InstancePortInfo {
            from_port: self.from_port.unwrap_or_default(),
            to_port: self.to_port.unwrap_or_default(),
            protocol: self.protocol,
            access_from: self.access_from,
            access_type: self.access_type,
            common_name: self.common_name,
            access_direction: self.access_direction,
            cidrs: self.cidrs,
            ipv6_cidrs: self.ipv6_cidrs,
            cidr_list_aliases: self.cidr_list_aliases,
        }
    }
}
