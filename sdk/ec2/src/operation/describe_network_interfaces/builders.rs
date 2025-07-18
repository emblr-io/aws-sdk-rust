// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::describe_network_interfaces::_describe_network_interfaces_output::DescribeNetworkInterfacesOutputBuilder;

pub use crate::operation::describe_network_interfaces::_describe_network_interfaces_input::DescribeNetworkInterfacesInputBuilder;

impl crate::operation::describe_network_interfaces::builders::DescribeNetworkInterfacesInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_network_interfaces::DescribeNetworkInterfacesError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.describe_network_interfaces();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `DescribeNetworkInterfaces`.
///
/// <p>Describes the specified network interfaces or all your network interfaces.</p>
/// <p>If you have a large number of network interfaces, the operation fails unless you use pagination or one of the following filters: <code>group-id</code>, <code>mac-address</code>, <code>private-dns-name</code>, <code>private-ip-address</code>, <code>subnet-id</code>, or <code>vpc-id</code>.</p><important>
/// <p>We strongly recommend using only paginated requests. Unpaginated requests are susceptible to throttling and timeouts.</p>
/// </important>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct DescribeNetworkInterfacesFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::describe_network_interfaces::builders::DescribeNetworkInterfacesInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput,
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesError,
    > for DescribeNetworkInterfacesFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput,
            crate::operation::describe_network_interfaces::DescribeNetworkInterfacesError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl DescribeNetworkInterfacesFluentBuilder {
    /// Creates a new `DescribeNetworkInterfacesFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the DescribeNetworkInterfaces as a reference.
    pub fn as_input(&self) -> &crate::operation::describe_network_interfaces::builders::DescribeNetworkInterfacesInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::describe_network_interfaces::DescribeNetworkInterfacesError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::describe_network_interfaces::DescribeNetworkInterfaces::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::describe_network_interfaces::DescribeNetworkInterfaces::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesOutput,
        crate::operation::describe_network_interfaces::DescribeNetworkInterfacesError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// Create a paginator for this request
    ///
    /// Paginators are used by calling [`send().await`](crate::operation::describe_network_interfaces::paginator::DescribeNetworkInterfacesPaginator::send) which returns a [`PaginationStream`](aws_smithy_async::future::pagination_stream::PaginationStream).
    pub fn into_paginator(self) -> crate::operation::describe_network_interfaces::paginator::DescribeNetworkInterfacesPaginator {
        crate::operation::describe_network_interfaces::paginator::DescribeNetworkInterfacesPaginator::new(self.handle, self.inner)
    }
    /// <p>The token returned from a previous paginated request. Pagination continues from the end of the items returned by the previous request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.next_token(input.into());
        self
    }
    /// <p>The token returned from a previous paginated request. Pagination continues from the end of the items returned by the previous request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_next_token(input);
        self
    }
    /// <p>The token returned from a previous paginated request. Pagination continues from the end of the items returned by the previous request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_next_token()
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. You cannot specify this parameter and the network interface IDs parameter in the same request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.inner = self.inner.max_results(input);
        self
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. You cannot specify this parameter and the network interface IDs parameter in the same request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_max_results(input);
        self
    }
    /// <p>The maximum number of items to return for this request. To get the next page of items, make another request with the token returned in the output. You cannot specify this parameter and the network interface IDs parameter in the same request. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination">Pagination</a>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        self.inner.get_max_results()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.inner = self.inner.dry_run(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.inner = self.inner.set_dry_run(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        self.inner.get_dry_run()
    }
    ///
    /// Appends an item to `NetworkInterfaceIds`.
    ///
    /// To override the contents of this collection use [`set_network_interface_ids`](Self::set_network_interface_ids).
    ///
    /// <p>The network interface IDs.</p>
    /// <p>Default: Describes all your network interfaces.</p>
    pub fn network_interface_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.network_interface_ids(input.into());
        self
    }
    /// <p>The network interface IDs.</p>
    /// <p>Default: Describes all your network interfaces.</p>
    pub fn set_network_interface_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inner = self.inner.set_network_interface_ids(input);
        self
    }
    /// <p>The network interface IDs.</p>
    /// <p>Default: Describes all your network interfaces.</p>
    pub fn get_network_interface_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        self.inner.get_network_interface_ids()
    }
    ///
    /// Appends an item to `Filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>association.allocation-id</code> - The allocation ID returned when you allocated the Elastic IP address (IPv4) for your network interface.</p></li>
    /// <li>
    /// <p><code>association.association-id</code> - The association ID returned when the network interface was associated with an IPv4 address.</p></li>
    /// <li>
    /// <p><code>addresses.association.owner-id</code> - The owner ID of the addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.association.public-ip</code> - The association ID returned when the network interface was associated with the Elastic IP address (IPv4).</p></li>
    /// <li>
    /// <p><code>addresses.primary</code> - Whether the private IPv4 address is the primary IP address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.private-ip-address</code> - The private IPv4 addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.ip-owner-id</code> - The owner of the Elastic IP address (IPv4) associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-ip</code> - The address of the Elastic IP address (IPv4) bound to the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-dns-name</code> - The public DNS name for the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>attachment.attach-time</code> - The time that the network interface was attached to an instance.</p></li>
    /// <li>
    /// <p><code>attachment.attachment-id</code> - The ID of the interface attachment.</p></li>
    /// <li>
    /// <p><code>attachment.delete-on-termination</code> - Indicates whether the attachment is deleted when an instance is terminated.</p></li>
    /// <li>
    /// <p><code>attachment.device-index</code> - The device index to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-id</code> - The ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-owner-id</code> - The owner ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.status</code> - The status of the attachment (<code>attaching</code> | <code>attached</code> | <code>detaching</code> | <code>detached</code>).</p></li>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone of the network interface.</p></li>
    /// <li>
    /// <p><code>description</code> - The description of the network interface.</p></li>
    /// <li>
    /// <p><code>group-id</code> - The ID of a security group associated with the network interface.</p></li>
    /// <li>
    /// <p><code>ipv6-addresses.ipv6-address</code> - An IPv6 address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>interface-type</code> - The type of network interface (<code>api_gateway_managed</code> | <code>aws_codestar_connections_managed</code> | <code>branch</code> | <code>ec2_instance_connect_endpoint</code> | <code>efa</code> | <code>efa-only</code> | <code>efs</code> | <code>evs</code> | <code>gateway_load_balancer</code> | <code>gateway_load_balancer_endpoint</code> | <code>global_accelerator_managed</code> | <code>interface</code> | <code>iot_rules_managed</code> | <code>lambda</code> | <code>load_balancer</code> | <code>nat_gateway</code> | <code>network_load_balancer</code> | <code>quicksight</code> | <code>transit_gateway</code> | <code>trunk</code> | <code>vpc_endpoint</code>).</p></li>
    /// <li>
    /// <p><code>mac-address</code> - The MAC address of the network interface.</p></li>
    /// <li>
    /// <p><code>network-interface-id</code> - The ID of the network interface.</p></li>
    /// <li>
    /// <p><code>operator.managed</code> - A Boolean that indicates whether this is a managed network interface.</p></li>
    /// <li>
    /// <p><code>operator.principal</code> - The principal that manages the network interface. Only valid for managed network interfaces, where <code>managed</code> is <code>true</code>.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the network interface owner.</p></li>
    /// <li>
    /// <p><code>private-dns-name</code> - The private DNS name of the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>private-ip-address</code> - The private IPv4 address or addresses of the network interface.</p></li>
    /// <li>
    /// <p><code>requester-id</code> - The alias or Amazon Web Services account ID of the principal or service that created the network interface.</p></li>
    /// <li>
    /// <p><code>requester-managed</code> - Indicates whether the network interface is being managed by an Amazon Web Services service (for example, Amazon Web Services Management Console, Auto Scaling, and so on).</p></li>
    /// <li>
    /// <p><code>source-dest-check</code> - Indicates whether the network interface performs source/destination checking. A value of <code>true</code> means checking is enabled, and <code>false</code> means checking is disabled. The value must be <code>false</code> for the network interface to perform network address translation (NAT) in your VPC.</p></li>
    /// <li>
    /// <p><code>status</code> - The status of the network interface. If the network interface is not attached to an instance, the status is <code>available</code>; if a network interface is attached to an instance the status is <code>in-use</code>.</p></li>
    /// <li>
    /// <p><code>subnet-id</code> - The ID of the subnet for the network interface.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC for the network interface.</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        self.inner = self.inner.filters(input);
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>association.allocation-id</code> - The allocation ID returned when you allocated the Elastic IP address (IPv4) for your network interface.</p></li>
    /// <li>
    /// <p><code>association.association-id</code> - The association ID returned when the network interface was associated with an IPv4 address.</p></li>
    /// <li>
    /// <p><code>addresses.association.owner-id</code> - The owner ID of the addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.association.public-ip</code> - The association ID returned when the network interface was associated with the Elastic IP address (IPv4).</p></li>
    /// <li>
    /// <p><code>addresses.primary</code> - Whether the private IPv4 address is the primary IP address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.private-ip-address</code> - The private IPv4 addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.ip-owner-id</code> - The owner of the Elastic IP address (IPv4) associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-ip</code> - The address of the Elastic IP address (IPv4) bound to the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-dns-name</code> - The public DNS name for the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>attachment.attach-time</code> - The time that the network interface was attached to an instance.</p></li>
    /// <li>
    /// <p><code>attachment.attachment-id</code> - The ID of the interface attachment.</p></li>
    /// <li>
    /// <p><code>attachment.delete-on-termination</code> - Indicates whether the attachment is deleted when an instance is terminated.</p></li>
    /// <li>
    /// <p><code>attachment.device-index</code> - The device index to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-id</code> - The ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-owner-id</code> - The owner ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.status</code> - The status of the attachment (<code>attaching</code> | <code>attached</code> | <code>detaching</code> | <code>detached</code>).</p></li>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone of the network interface.</p></li>
    /// <li>
    /// <p><code>description</code> - The description of the network interface.</p></li>
    /// <li>
    /// <p><code>group-id</code> - The ID of a security group associated with the network interface.</p></li>
    /// <li>
    /// <p><code>ipv6-addresses.ipv6-address</code> - An IPv6 address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>interface-type</code> - The type of network interface (<code>api_gateway_managed</code> | <code>aws_codestar_connections_managed</code> | <code>branch</code> | <code>ec2_instance_connect_endpoint</code> | <code>efa</code> | <code>efa-only</code> | <code>efs</code> | <code>evs</code> | <code>gateway_load_balancer</code> | <code>gateway_load_balancer_endpoint</code> | <code>global_accelerator_managed</code> | <code>interface</code> | <code>iot_rules_managed</code> | <code>lambda</code> | <code>load_balancer</code> | <code>nat_gateway</code> | <code>network_load_balancer</code> | <code>quicksight</code> | <code>transit_gateway</code> | <code>trunk</code> | <code>vpc_endpoint</code>).</p></li>
    /// <li>
    /// <p><code>mac-address</code> - The MAC address of the network interface.</p></li>
    /// <li>
    /// <p><code>network-interface-id</code> - The ID of the network interface.</p></li>
    /// <li>
    /// <p><code>operator.managed</code> - A Boolean that indicates whether this is a managed network interface.</p></li>
    /// <li>
    /// <p><code>operator.principal</code> - The principal that manages the network interface. Only valid for managed network interfaces, where <code>managed</code> is <code>true</code>.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the network interface owner.</p></li>
    /// <li>
    /// <p><code>private-dns-name</code> - The private DNS name of the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>private-ip-address</code> - The private IPv4 address or addresses of the network interface.</p></li>
    /// <li>
    /// <p><code>requester-id</code> - The alias or Amazon Web Services account ID of the principal or service that created the network interface.</p></li>
    /// <li>
    /// <p><code>requester-managed</code> - Indicates whether the network interface is being managed by an Amazon Web Services service (for example, Amazon Web Services Management Console, Auto Scaling, and so on).</p></li>
    /// <li>
    /// <p><code>source-dest-check</code> - Indicates whether the network interface performs source/destination checking. A value of <code>true</code> means checking is enabled, and <code>false</code> means checking is disabled. The value must be <code>false</code> for the network interface to perform network address translation (NAT) in your VPC.</p></li>
    /// <li>
    /// <p><code>status</code> - The status of the network interface. If the network interface is not attached to an instance, the status is <code>available</code>; if a network interface is attached to an instance the status is <code>in-use</code>.</p></li>
    /// <li>
    /// <p><code>subnet-id</code> - The ID of the subnet for the network interface.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC for the network interface.</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.inner = self.inner.set_filters(input);
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>association.allocation-id</code> - The allocation ID returned when you allocated the Elastic IP address (IPv4) for your network interface.</p></li>
    /// <li>
    /// <p><code>association.association-id</code> - The association ID returned when the network interface was associated with an IPv4 address.</p></li>
    /// <li>
    /// <p><code>addresses.association.owner-id</code> - The owner ID of the addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.association.public-ip</code> - The association ID returned when the network interface was associated with the Elastic IP address (IPv4).</p></li>
    /// <li>
    /// <p><code>addresses.primary</code> - Whether the private IPv4 address is the primary IP address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>addresses.private-ip-address</code> - The private IPv4 addresses associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.ip-owner-id</code> - The owner of the Elastic IP address (IPv4) associated with the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-ip</code> - The address of the Elastic IP address (IPv4) bound to the network interface.</p></li>
    /// <li>
    /// <p><code>association.public-dns-name</code> - The public DNS name for the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>attachment.attach-time</code> - The time that the network interface was attached to an instance.</p></li>
    /// <li>
    /// <p><code>attachment.attachment-id</code> - The ID of the interface attachment.</p></li>
    /// <li>
    /// <p><code>attachment.delete-on-termination</code> - Indicates whether the attachment is deleted when an instance is terminated.</p></li>
    /// <li>
    /// <p><code>attachment.device-index</code> - The device index to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-id</code> - The ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.instance-owner-id</code> - The owner ID of the instance to which the network interface is attached.</p></li>
    /// <li>
    /// <p><code>attachment.status</code> - The status of the attachment (<code>attaching</code> | <code>attached</code> | <code>detaching</code> | <code>detached</code>).</p></li>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone of the network interface.</p></li>
    /// <li>
    /// <p><code>description</code> - The description of the network interface.</p></li>
    /// <li>
    /// <p><code>group-id</code> - The ID of a security group associated with the network interface.</p></li>
    /// <li>
    /// <p><code>ipv6-addresses.ipv6-address</code> - An IPv6 address associated with the network interface.</p></li>
    /// <li>
    /// <p><code>interface-type</code> - The type of network interface (<code>api_gateway_managed</code> | <code>aws_codestar_connections_managed</code> | <code>branch</code> | <code>ec2_instance_connect_endpoint</code> | <code>efa</code> | <code>efa-only</code> | <code>efs</code> | <code>evs</code> | <code>gateway_load_balancer</code> | <code>gateway_load_balancer_endpoint</code> | <code>global_accelerator_managed</code> | <code>interface</code> | <code>iot_rules_managed</code> | <code>lambda</code> | <code>load_balancer</code> | <code>nat_gateway</code> | <code>network_load_balancer</code> | <code>quicksight</code> | <code>transit_gateway</code> | <code>trunk</code> | <code>vpc_endpoint</code>).</p></li>
    /// <li>
    /// <p><code>mac-address</code> - The MAC address of the network interface.</p></li>
    /// <li>
    /// <p><code>network-interface-id</code> - The ID of the network interface.</p></li>
    /// <li>
    /// <p><code>operator.managed</code> - A Boolean that indicates whether this is a managed network interface.</p></li>
    /// <li>
    /// <p><code>operator.principal</code> - The principal that manages the network interface. Only valid for managed network interfaces, where <code>managed</code> is <code>true</code>.</p></li>
    /// <li>
    /// <p><code>owner-id</code> - The Amazon Web Services account ID of the network interface owner.</p></li>
    /// <li>
    /// <p><code>private-dns-name</code> - The private DNS name of the network interface (IPv4).</p></li>
    /// <li>
    /// <p><code>private-ip-address</code> - The private IPv4 address or addresses of the network interface.</p></li>
    /// <li>
    /// <p><code>requester-id</code> - The alias or Amazon Web Services account ID of the principal or service that created the network interface.</p></li>
    /// <li>
    /// <p><code>requester-managed</code> - Indicates whether the network interface is being managed by an Amazon Web Services service (for example, Amazon Web Services Management Console, Auto Scaling, and so on).</p></li>
    /// <li>
    /// <p><code>source-dest-check</code> - Indicates whether the network interface performs source/destination checking. A value of <code>true</code> means checking is enabled, and <code>false</code> means checking is disabled. The value must be <code>false</code> for the network interface to perform network address translation (NAT) in your VPC.</p></li>
    /// <li>
    /// <p><code>status</code> - The status of the network interface. If the network interface is not attached to an instance, the status is <code>available</code>; if a network interface is attached to an instance the status is <code>in-use</code>.</p></li>
    /// <li>
    /// <p><code>subnet-id</code> - The ID of the subnet for the network interface.</p></li>
    /// <li>
    /// <p><code>tag</code>:<key>
    /// - The key/value combination of a tag assigned to the resource. Use the tag key in the filter name and the tag value as the filter value. For example, to find all resources that have a tag with the key
    /// <code>Owner</code> and the value
    /// <code>TeamA</code>, specify
    /// <code>tag:Owner</code> for the filter name and
    /// <code>TeamA</code> for the filter value.
    /// </key></p></li>
    /// <li>
    /// <p><code>tag-key</code> - The key of a tag assigned to the resource. Use this filter to find all resources assigned a tag with a specific key, regardless of the tag value.</p></li>
    /// <li>
    /// <p><code>vpc-id</code> - The ID of the VPC for the network interface.</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        self.inner.get_filters()
    }
}
