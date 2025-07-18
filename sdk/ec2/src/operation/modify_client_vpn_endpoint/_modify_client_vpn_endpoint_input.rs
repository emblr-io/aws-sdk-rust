// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyClientVpnEndpointInput {
    /// <p>The ID of the Client VPN endpoint to modify.</p>
    pub client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the server certificate to be used. The server certificate must be provisioned in Certificate Manager (ACM).</p>
    pub server_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>Information about the client connection logging options.</p>
    /// <p>If you enable client connection logging, data about client connections is sent to a Cloudwatch Logs log stream. The following information is logged:</p>
    /// <ul>
    /// <li>
    /// <p>Client connection requests</p></li>
    /// <li>
    /// <p>Client connection results (successful and unsuccessful)</p></li>
    /// <li>
    /// <p>Reasons for unsuccessful client connection requests</p></li>
    /// <li>
    /// <p>Client connection termination time</p></li>
    /// </ul>
    pub connection_log_options: ::std::option::Option<crate::types::ConnectionLogOptions>,
    /// <p>Information about the DNS servers to be used by Client VPN connections. A Client VPN endpoint can have up to two DNS servers.</p>
    pub dns_servers: ::std::option::Option<crate::types::DnsServersOptionsModifyStructure>,
    /// <p>The port number to assign to the Client VPN endpoint for TCP and UDP traffic.</p>
    /// <p>Valid Values: <code>443</code> | <code>1194</code></p>
    /// <p>Default Value: <code>443</code></p>
    pub vpn_port: ::std::option::Option<i32>,
    /// <p>A brief description of the Client VPN endpoint.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the VPN is split-tunnel.</p>
    /// <p>For information about split-tunnel VPN endpoints, see <a href="https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/split-tunnel-vpn.html">Split-tunnel Client VPN endpoint</a> in the <i>Client VPN Administrator Guide</i>.</p>
    pub split_tunnel: ::std::option::Option<bool>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The IDs of one or more security groups to apply to the target network.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The ID of the VPC to associate with the Client VPN endpoint.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Specify whether to enable the self-service portal for the Client VPN endpoint.</p>
    pub self_service_portal: ::std::option::Option<crate::types::SelfServicePortal>,
    /// <p>The options for managing connection authorization for new client connections.</p>
    pub client_connect_options: ::std::option::Option<crate::types::ClientConnectOptions>,
    /// <p>The maximum VPN session duration time in hours.</p>
    /// <p>Valid values: <code>8 | 10 | 12 | 24</code></p>
    /// <p>Default value: <code>24</code></p>
    pub session_timeout_hours: ::std::option::Option<i32>,
    /// <p>Options for enabling a customizable text banner that will be displayed on Amazon Web Services provided clients when a VPN session is established.</p>
    pub client_login_banner_options: ::std::option::Option<crate::types::ClientLoginBannerOptions>,
    /// <p>Client route enforcement is a feature of the Client VPN service that helps enforce administrator defined routes on devices connected through the VPN. T his feature helps improve your security posture by ensuring that network traffic originating from a connected client is not inadvertently sent outside the VPN tunnel.</p>
    /// <p>Client route enforcement works by monitoring the route table of a connected device for routing policy changes to the VPN connection. If the feature detects any VPN routing policy modifications, it will automatically force an update to the route table, reverting it back to the expected route configurations.</p>
    pub client_route_enforcement_options: ::std::option::Option<crate::types::ClientRouteEnforcementOptions>,
    /// <p>Indicates whether the client VPN session is disconnected after the maximum timeout specified in <code>sessionTimeoutHours</code> is reached. If <code>true</code>, users are prompted to reconnect client VPN. If <code>false</code>, client VPN attempts to reconnect automatically. The default value is <code>true</code>.</p>
    pub disconnect_on_session_timeout: ::std::option::Option<bool>,
}
impl ModifyClientVpnEndpointInput {
    /// <p>The ID of the Client VPN endpoint to modify.</p>
    pub fn client_vpn_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.client_vpn_endpoint_id.as_deref()
    }
    /// <p>The ARN of the server certificate to be used. The server certificate must be provisioned in Certificate Manager (ACM).</p>
    pub fn server_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.server_certificate_arn.as_deref()
    }
    /// <p>Information about the client connection logging options.</p>
    /// <p>If you enable client connection logging, data about client connections is sent to a Cloudwatch Logs log stream. The following information is logged:</p>
    /// <ul>
    /// <li>
    /// <p>Client connection requests</p></li>
    /// <li>
    /// <p>Client connection results (successful and unsuccessful)</p></li>
    /// <li>
    /// <p>Reasons for unsuccessful client connection requests</p></li>
    /// <li>
    /// <p>Client connection termination time</p></li>
    /// </ul>
    pub fn connection_log_options(&self) -> ::std::option::Option<&crate::types::ConnectionLogOptions> {
        self.connection_log_options.as_ref()
    }
    /// <p>Information about the DNS servers to be used by Client VPN connections. A Client VPN endpoint can have up to two DNS servers.</p>
    pub fn dns_servers(&self) -> ::std::option::Option<&crate::types::DnsServersOptionsModifyStructure> {
        self.dns_servers.as_ref()
    }
    /// <p>The port number to assign to the Client VPN endpoint for TCP and UDP traffic.</p>
    /// <p>Valid Values: <code>443</code> | <code>1194</code></p>
    /// <p>Default Value: <code>443</code></p>
    pub fn vpn_port(&self) -> ::std::option::Option<i32> {
        self.vpn_port
    }
    /// <p>A brief description of the Client VPN endpoint.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Indicates whether the VPN is split-tunnel.</p>
    /// <p>For information about split-tunnel VPN endpoints, see <a href="https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/split-tunnel-vpn.html">Split-tunnel Client VPN endpoint</a> in the <i>Client VPN Administrator Guide</i>.</p>
    pub fn split_tunnel(&self) -> ::std::option::Option<bool> {
        self.split_tunnel
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The IDs of one or more security groups to apply to the target network.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the VPC to associate with the Client VPN endpoint.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Specify whether to enable the self-service portal for the Client VPN endpoint.</p>
    pub fn self_service_portal(&self) -> ::std::option::Option<&crate::types::SelfServicePortal> {
        self.self_service_portal.as_ref()
    }
    /// <p>The options for managing connection authorization for new client connections.</p>
    pub fn client_connect_options(&self) -> ::std::option::Option<&crate::types::ClientConnectOptions> {
        self.client_connect_options.as_ref()
    }
    /// <p>The maximum VPN session duration time in hours.</p>
    /// <p>Valid values: <code>8 | 10 | 12 | 24</code></p>
    /// <p>Default value: <code>24</code></p>
    pub fn session_timeout_hours(&self) -> ::std::option::Option<i32> {
        self.session_timeout_hours
    }
    /// <p>Options for enabling a customizable text banner that will be displayed on Amazon Web Services provided clients when a VPN session is established.</p>
    pub fn client_login_banner_options(&self) -> ::std::option::Option<&crate::types::ClientLoginBannerOptions> {
        self.client_login_banner_options.as_ref()
    }
    /// <p>Client route enforcement is a feature of the Client VPN service that helps enforce administrator defined routes on devices connected through the VPN. T his feature helps improve your security posture by ensuring that network traffic originating from a connected client is not inadvertently sent outside the VPN tunnel.</p>
    /// <p>Client route enforcement works by monitoring the route table of a connected device for routing policy changes to the VPN connection. If the feature detects any VPN routing policy modifications, it will automatically force an update to the route table, reverting it back to the expected route configurations.</p>
    pub fn client_route_enforcement_options(&self) -> ::std::option::Option<&crate::types::ClientRouteEnforcementOptions> {
        self.client_route_enforcement_options.as_ref()
    }
    /// <p>Indicates whether the client VPN session is disconnected after the maximum timeout specified in <code>sessionTimeoutHours</code> is reached. If <code>true</code>, users are prompted to reconnect client VPN. If <code>false</code>, client VPN attempts to reconnect automatically. The default value is <code>true</code>.</p>
    pub fn disconnect_on_session_timeout(&self) -> ::std::option::Option<bool> {
        self.disconnect_on_session_timeout
    }
}
impl ModifyClientVpnEndpointInput {
    /// Creates a new builder-style object to manufacture [`ModifyClientVpnEndpointInput`](crate::operation::modify_client_vpn_endpoint::ModifyClientVpnEndpointInput).
    pub fn builder() -> crate::operation::modify_client_vpn_endpoint::builders::ModifyClientVpnEndpointInputBuilder {
        crate::operation::modify_client_vpn_endpoint::builders::ModifyClientVpnEndpointInputBuilder::default()
    }
}

/// A builder for [`ModifyClientVpnEndpointInput`](crate::operation::modify_client_vpn_endpoint::ModifyClientVpnEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyClientVpnEndpointInputBuilder {
    pub(crate) client_vpn_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) server_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) connection_log_options: ::std::option::Option<crate::types::ConnectionLogOptions>,
    pub(crate) dns_servers: ::std::option::Option<crate::types::DnsServersOptionsModifyStructure>,
    pub(crate) vpn_port: ::std::option::Option<i32>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) split_tunnel: ::std::option::Option<bool>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) self_service_portal: ::std::option::Option<crate::types::SelfServicePortal>,
    pub(crate) client_connect_options: ::std::option::Option<crate::types::ClientConnectOptions>,
    pub(crate) session_timeout_hours: ::std::option::Option<i32>,
    pub(crate) client_login_banner_options: ::std::option::Option<crate::types::ClientLoginBannerOptions>,
    pub(crate) client_route_enforcement_options: ::std::option::Option<crate::types::ClientRouteEnforcementOptions>,
    pub(crate) disconnect_on_session_timeout: ::std::option::Option<bool>,
}
impl ModifyClientVpnEndpointInputBuilder {
    /// <p>The ID of the Client VPN endpoint to modify.</p>
    /// This field is required.
    pub fn client_vpn_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Client VPN endpoint to modify.</p>
    pub fn set_client_vpn_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_vpn_endpoint_id = input;
        self
    }
    /// <p>The ID of the Client VPN endpoint to modify.</p>
    pub fn get_client_vpn_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_vpn_endpoint_id
    }
    /// <p>The ARN of the server certificate to be used. The server certificate must be provisioned in Certificate Manager (ACM).</p>
    pub fn server_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the server certificate to be used. The server certificate must be provisioned in Certificate Manager (ACM).</p>
    pub fn set_server_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_certificate_arn = input;
        self
    }
    /// <p>The ARN of the server certificate to be used. The server certificate must be provisioned in Certificate Manager (ACM).</p>
    pub fn get_server_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_certificate_arn
    }
    /// <p>Information about the client connection logging options.</p>
    /// <p>If you enable client connection logging, data about client connections is sent to a Cloudwatch Logs log stream. The following information is logged:</p>
    /// <ul>
    /// <li>
    /// <p>Client connection requests</p></li>
    /// <li>
    /// <p>Client connection results (successful and unsuccessful)</p></li>
    /// <li>
    /// <p>Reasons for unsuccessful client connection requests</p></li>
    /// <li>
    /// <p>Client connection termination time</p></li>
    /// </ul>
    pub fn connection_log_options(mut self, input: crate::types::ConnectionLogOptions) -> Self {
        self.connection_log_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the client connection logging options.</p>
    /// <p>If you enable client connection logging, data about client connections is sent to a Cloudwatch Logs log stream. The following information is logged:</p>
    /// <ul>
    /// <li>
    /// <p>Client connection requests</p></li>
    /// <li>
    /// <p>Client connection results (successful and unsuccessful)</p></li>
    /// <li>
    /// <p>Reasons for unsuccessful client connection requests</p></li>
    /// <li>
    /// <p>Client connection termination time</p></li>
    /// </ul>
    pub fn set_connection_log_options(mut self, input: ::std::option::Option<crate::types::ConnectionLogOptions>) -> Self {
        self.connection_log_options = input;
        self
    }
    /// <p>Information about the client connection logging options.</p>
    /// <p>If you enable client connection logging, data about client connections is sent to a Cloudwatch Logs log stream. The following information is logged:</p>
    /// <ul>
    /// <li>
    /// <p>Client connection requests</p></li>
    /// <li>
    /// <p>Client connection results (successful and unsuccessful)</p></li>
    /// <li>
    /// <p>Reasons for unsuccessful client connection requests</p></li>
    /// <li>
    /// <p>Client connection termination time</p></li>
    /// </ul>
    pub fn get_connection_log_options(&self) -> &::std::option::Option<crate::types::ConnectionLogOptions> {
        &self.connection_log_options
    }
    /// <p>Information about the DNS servers to be used by Client VPN connections. A Client VPN endpoint can have up to two DNS servers.</p>
    pub fn dns_servers(mut self, input: crate::types::DnsServersOptionsModifyStructure) -> Self {
        self.dns_servers = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the DNS servers to be used by Client VPN connections. A Client VPN endpoint can have up to two DNS servers.</p>
    pub fn set_dns_servers(mut self, input: ::std::option::Option<crate::types::DnsServersOptionsModifyStructure>) -> Self {
        self.dns_servers = input;
        self
    }
    /// <p>Information about the DNS servers to be used by Client VPN connections. A Client VPN endpoint can have up to two DNS servers.</p>
    pub fn get_dns_servers(&self) -> &::std::option::Option<crate::types::DnsServersOptionsModifyStructure> {
        &self.dns_servers
    }
    /// <p>The port number to assign to the Client VPN endpoint for TCP and UDP traffic.</p>
    /// <p>Valid Values: <code>443</code> | <code>1194</code></p>
    /// <p>Default Value: <code>443</code></p>
    pub fn vpn_port(mut self, input: i32) -> Self {
        self.vpn_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port number to assign to the Client VPN endpoint for TCP and UDP traffic.</p>
    /// <p>Valid Values: <code>443</code> | <code>1194</code></p>
    /// <p>Default Value: <code>443</code></p>
    pub fn set_vpn_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.vpn_port = input;
        self
    }
    /// <p>The port number to assign to the Client VPN endpoint for TCP and UDP traffic.</p>
    /// <p>Valid Values: <code>443</code> | <code>1194</code></p>
    /// <p>Default Value: <code>443</code></p>
    pub fn get_vpn_port(&self) -> &::std::option::Option<i32> {
        &self.vpn_port
    }
    /// <p>A brief description of the Client VPN endpoint.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the Client VPN endpoint.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description of the Client VPN endpoint.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Indicates whether the VPN is split-tunnel.</p>
    /// <p>For information about split-tunnel VPN endpoints, see <a href="https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/split-tunnel-vpn.html">Split-tunnel Client VPN endpoint</a> in the <i>Client VPN Administrator Guide</i>.</p>
    pub fn split_tunnel(mut self, input: bool) -> Self {
        self.split_tunnel = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the VPN is split-tunnel.</p>
    /// <p>For information about split-tunnel VPN endpoints, see <a href="https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/split-tunnel-vpn.html">Split-tunnel Client VPN endpoint</a> in the <i>Client VPN Administrator Guide</i>.</p>
    pub fn set_split_tunnel(mut self, input: ::std::option::Option<bool>) -> Self {
        self.split_tunnel = input;
        self
    }
    /// <p>Indicates whether the VPN is split-tunnel.</p>
    /// <p>For information about split-tunnel VPN endpoints, see <a href="https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/split-tunnel-vpn.html">Split-tunnel Client VPN endpoint</a> in the <i>Client VPN Administrator Guide</i>.</p>
    pub fn get_split_tunnel(&self) -> &::std::option::Option<bool> {
        &self.split_tunnel
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>The IDs of one or more security groups to apply to the target network.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of one or more security groups to apply to the target network.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>The IDs of one or more security groups to apply to the target network.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// <p>The ID of the VPC to associate with the Client VPN endpoint.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the VPC to associate with the Client VPN endpoint.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The ID of the VPC to associate with the Client VPN endpoint.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>Specify whether to enable the self-service portal for the Client VPN endpoint.</p>
    pub fn self_service_portal(mut self, input: crate::types::SelfServicePortal) -> Self {
        self.self_service_portal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify whether to enable the self-service portal for the Client VPN endpoint.</p>
    pub fn set_self_service_portal(mut self, input: ::std::option::Option<crate::types::SelfServicePortal>) -> Self {
        self.self_service_portal = input;
        self
    }
    /// <p>Specify whether to enable the self-service portal for the Client VPN endpoint.</p>
    pub fn get_self_service_portal(&self) -> &::std::option::Option<crate::types::SelfServicePortal> {
        &self.self_service_portal
    }
    /// <p>The options for managing connection authorization for new client connections.</p>
    pub fn client_connect_options(mut self, input: crate::types::ClientConnectOptions) -> Self {
        self.client_connect_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for managing connection authorization for new client connections.</p>
    pub fn set_client_connect_options(mut self, input: ::std::option::Option<crate::types::ClientConnectOptions>) -> Self {
        self.client_connect_options = input;
        self
    }
    /// <p>The options for managing connection authorization for new client connections.</p>
    pub fn get_client_connect_options(&self) -> &::std::option::Option<crate::types::ClientConnectOptions> {
        &self.client_connect_options
    }
    /// <p>The maximum VPN session duration time in hours.</p>
    /// <p>Valid values: <code>8 | 10 | 12 | 24</code></p>
    /// <p>Default value: <code>24</code></p>
    pub fn session_timeout_hours(mut self, input: i32) -> Self {
        self.session_timeout_hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum VPN session duration time in hours.</p>
    /// <p>Valid values: <code>8 | 10 | 12 | 24</code></p>
    /// <p>Default value: <code>24</code></p>
    pub fn set_session_timeout_hours(mut self, input: ::std::option::Option<i32>) -> Self {
        self.session_timeout_hours = input;
        self
    }
    /// <p>The maximum VPN session duration time in hours.</p>
    /// <p>Valid values: <code>8 | 10 | 12 | 24</code></p>
    /// <p>Default value: <code>24</code></p>
    pub fn get_session_timeout_hours(&self) -> &::std::option::Option<i32> {
        &self.session_timeout_hours
    }
    /// <p>Options for enabling a customizable text banner that will be displayed on Amazon Web Services provided clients when a VPN session is established.</p>
    pub fn client_login_banner_options(mut self, input: crate::types::ClientLoginBannerOptions) -> Self {
        self.client_login_banner_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options for enabling a customizable text banner that will be displayed on Amazon Web Services provided clients when a VPN session is established.</p>
    pub fn set_client_login_banner_options(mut self, input: ::std::option::Option<crate::types::ClientLoginBannerOptions>) -> Self {
        self.client_login_banner_options = input;
        self
    }
    /// <p>Options for enabling a customizable text banner that will be displayed on Amazon Web Services provided clients when a VPN session is established.</p>
    pub fn get_client_login_banner_options(&self) -> &::std::option::Option<crate::types::ClientLoginBannerOptions> {
        &self.client_login_banner_options
    }
    /// <p>Client route enforcement is a feature of the Client VPN service that helps enforce administrator defined routes on devices connected through the VPN. T his feature helps improve your security posture by ensuring that network traffic originating from a connected client is not inadvertently sent outside the VPN tunnel.</p>
    /// <p>Client route enforcement works by monitoring the route table of a connected device for routing policy changes to the VPN connection. If the feature detects any VPN routing policy modifications, it will automatically force an update to the route table, reverting it back to the expected route configurations.</p>
    pub fn client_route_enforcement_options(mut self, input: crate::types::ClientRouteEnforcementOptions) -> Self {
        self.client_route_enforcement_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Client route enforcement is a feature of the Client VPN service that helps enforce administrator defined routes on devices connected through the VPN. T his feature helps improve your security posture by ensuring that network traffic originating from a connected client is not inadvertently sent outside the VPN tunnel.</p>
    /// <p>Client route enforcement works by monitoring the route table of a connected device for routing policy changes to the VPN connection. If the feature detects any VPN routing policy modifications, it will automatically force an update to the route table, reverting it back to the expected route configurations.</p>
    pub fn set_client_route_enforcement_options(mut self, input: ::std::option::Option<crate::types::ClientRouteEnforcementOptions>) -> Self {
        self.client_route_enforcement_options = input;
        self
    }
    /// <p>Client route enforcement is a feature of the Client VPN service that helps enforce administrator defined routes on devices connected through the VPN. T his feature helps improve your security posture by ensuring that network traffic originating from a connected client is not inadvertently sent outside the VPN tunnel.</p>
    /// <p>Client route enforcement works by monitoring the route table of a connected device for routing policy changes to the VPN connection. If the feature detects any VPN routing policy modifications, it will automatically force an update to the route table, reverting it back to the expected route configurations.</p>
    pub fn get_client_route_enforcement_options(&self) -> &::std::option::Option<crate::types::ClientRouteEnforcementOptions> {
        &self.client_route_enforcement_options
    }
    /// <p>Indicates whether the client VPN session is disconnected after the maximum timeout specified in <code>sessionTimeoutHours</code> is reached. If <code>true</code>, users are prompted to reconnect client VPN. If <code>false</code>, client VPN attempts to reconnect automatically. The default value is <code>true</code>.</p>
    pub fn disconnect_on_session_timeout(mut self, input: bool) -> Self {
        self.disconnect_on_session_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the client VPN session is disconnected after the maximum timeout specified in <code>sessionTimeoutHours</code> is reached. If <code>true</code>, users are prompted to reconnect client VPN. If <code>false</code>, client VPN attempts to reconnect automatically. The default value is <code>true</code>.</p>
    pub fn set_disconnect_on_session_timeout(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disconnect_on_session_timeout = input;
        self
    }
    /// <p>Indicates whether the client VPN session is disconnected after the maximum timeout specified in <code>sessionTimeoutHours</code> is reached. If <code>true</code>, users are prompted to reconnect client VPN. If <code>false</code>, client VPN attempts to reconnect automatically. The default value is <code>true</code>.</p>
    pub fn get_disconnect_on_session_timeout(&self) -> &::std::option::Option<bool> {
        &self.disconnect_on_session_timeout
    }
    /// Consumes the builder and constructs a [`ModifyClientVpnEndpointInput`](crate::operation::modify_client_vpn_endpoint::ModifyClientVpnEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_client_vpn_endpoint::ModifyClientVpnEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_client_vpn_endpoint::ModifyClientVpnEndpointInput {
            client_vpn_endpoint_id: self.client_vpn_endpoint_id,
            server_certificate_arn: self.server_certificate_arn,
            connection_log_options: self.connection_log_options,
            dns_servers: self.dns_servers,
            vpn_port: self.vpn_port,
            description: self.description,
            split_tunnel: self.split_tunnel,
            dry_run: self.dry_run,
            security_group_ids: self.security_group_ids,
            vpc_id: self.vpc_id,
            self_service_portal: self.self_service_portal,
            client_connect_options: self.client_connect_options,
            session_timeout_hours: self.session_timeout_hours,
            client_login_banner_options: self.client_login_banner_options,
            client_route_enforcement_options: self.client_route_enforcement_options,
            disconnect_on_session_timeout: self.disconnect_on_session_timeout,
        })
    }
}
