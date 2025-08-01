// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateNetworkAnalyzerConfigurationInput {
    /// <p>Name of the network analyzer configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Trace content for your wireless devices, gateways, and multicast groups.</p>
    pub trace_content: ::std::option::Option<crate::types::TraceContent>,
    /// <p>Wireless device resources to add to the network analyzer configuration. Provide the <code>WirelessDeviceId</code> of the resource to add in the input array.</p>
    pub wireless_devices: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Wireless gateway resources to add to the network analyzer configuration. Provide the <code>WirelessGatewayId</code> of the resource to add in the input array.</p>
    pub wireless_gateways: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The description of the new resource.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The tag to attach to the specified resource. Tags are metadata that you can use to manage a resource.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Each resource must have a unique client request token. The client token is used to implement idempotency. It ensures that the request completes no more than one time. If you retry a request with the same token and the same parameters, the request will complete successfully. However, if you try to create a new resource using the same token but different parameters, an HTTP 409 conflict occurs. If you omit this value, AWS SDKs will automatically generate a unique client request. For more information about idempotency, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency in Amazon EC2 API requests</a>.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>Multicast Group resources to add to the network analyzer configruation. Provide the <code>MulticastGroupId</code> of the resource to add in the input array.</p>
    pub multicast_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateNetworkAnalyzerConfigurationInput {
    /// <p>Name of the network analyzer configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Trace content for your wireless devices, gateways, and multicast groups.</p>
    pub fn trace_content(&self) -> ::std::option::Option<&crate::types::TraceContent> {
        self.trace_content.as_ref()
    }
    /// <p>Wireless device resources to add to the network analyzer configuration. Provide the <code>WirelessDeviceId</code> of the resource to add in the input array.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.wireless_devices.is_none()`.
    pub fn wireless_devices(&self) -> &[::std::string::String] {
        self.wireless_devices.as_deref().unwrap_or_default()
    }
    /// <p>Wireless gateway resources to add to the network analyzer configuration. Provide the <code>WirelessGatewayId</code> of the resource to add in the input array.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.wireless_gateways.is_none()`.
    pub fn wireless_gateways(&self) -> &[::std::string::String] {
        self.wireless_gateways.as_deref().unwrap_or_default()
    }
    /// <p>The description of the new resource.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The tag to attach to the specified resource. Tags are metadata that you can use to manage a resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Each resource must have a unique client request token. The client token is used to implement idempotency. It ensures that the request completes no more than one time. If you retry a request with the same token and the same parameters, the request will complete successfully. However, if you try to create a new resource using the same token but different parameters, an HTTP 409 conflict occurs. If you omit this value, AWS SDKs will automatically generate a unique client request. For more information about idempotency, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency in Amazon EC2 API requests</a>.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>Multicast Group resources to add to the network analyzer configruation. Provide the <code>MulticastGroupId</code> of the resource to add in the input array.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.multicast_groups.is_none()`.
    pub fn multicast_groups(&self) -> &[::std::string::String] {
        self.multicast_groups.as_deref().unwrap_or_default()
    }
}
impl CreateNetworkAnalyzerConfigurationInput {
    /// Creates a new builder-style object to manufacture [`CreateNetworkAnalyzerConfigurationInput`](crate::operation::create_network_analyzer_configuration::CreateNetworkAnalyzerConfigurationInput).
    pub fn builder() -> crate::operation::create_network_analyzer_configuration::builders::CreateNetworkAnalyzerConfigurationInputBuilder {
        crate::operation::create_network_analyzer_configuration::builders::CreateNetworkAnalyzerConfigurationInputBuilder::default()
    }
}

/// A builder for [`CreateNetworkAnalyzerConfigurationInput`](crate::operation::create_network_analyzer_configuration::CreateNetworkAnalyzerConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateNetworkAnalyzerConfigurationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) trace_content: ::std::option::Option<crate::types::TraceContent>,
    pub(crate) wireless_devices: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) wireless_gateways: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) multicast_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CreateNetworkAnalyzerConfigurationInputBuilder {
    /// <p>Name of the network analyzer configuration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the network analyzer configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the network analyzer configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Trace content for your wireless devices, gateways, and multicast groups.</p>
    pub fn trace_content(mut self, input: crate::types::TraceContent) -> Self {
        self.trace_content = ::std::option::Option::Some(input);
        self
    }
    /// <p>Trace content for your wireless devices, gateways, and multicast groups.</p>
    pub fn set_trace_content(mut self, input: ::std::option::Option<crate::types::TraceContent>) -> Self {
        self.trace_content = input;
        self
    }
    /// <p>Trace content for your wireless devices, gateways, and multicast groups.</p>
    pub fn get_trace_content(&self) -> &::std::option::Option<crate::types::TraceContent> {
        &self.trace_content
    }
    /// Appends an item to `wireless_devices`.
    ///
    /// To override the contents of this collection use [`set_wireless_devices`](Self::set_wireless_devices).
    ///
    /// <p>Wireless device resources to add to the network analyzer configuration. Provide the <code>WirelessDeviceId</code> of the resource to add in the input array.</p>
    pub fn wireless_devices(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.wireless_devices.unwrap_or_default();
        v.push(input.into());
        self.wireless_devices = ::std::option::Option::Some(v);
        self
    }
    /// <p>Wireless device resources to add to the network analyzer configuration. Provide the <code>WirelessDeviceId</code> of the resource to add in the input array.</p>
    pub fn set_wireless_devices(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.wireless_devices = input;
        self
    }
    /// <p>Wireless device resources to add to the network analyzer configuration. Provide the <code>WirelessDeviceId</code> of the resource to add in the input array.</p>
    pub fn get_wireless_devices(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.wireless_devices
    }
    /// Appends an item to `wireless_gateways`.
    ///
    /// To override the contents of this collection use [`set_wireless_gateways`](Self::set_wireless_gateways).
    ///
    /// <p>Wireless gateway resources to add to the network analyzer configuration. Provide the <code>WirelessGatewayId</code> of the resource to add in the input array.</p>
    pub fn wireless_gateways(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.wireless_gateways.unwrap_or_default();
        v.push(input.into());
        self.wireless_gateways = ::std::option::Option::Some(v);
        self
    }
    /// <p>Wireless gateway resources to add to the network analyzer configuration. Provide the <code>WirelessGatewayId</code> of the resource to add in the input array.</p>
    pub fn set_wireless_gateways(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.wireless_gateways = input;
        self
    }
    /// <p>Wireless gateway resources to add to the network analyzer configuration. Provide the <code>WirelessGatewayId</code> of the resource to add in the input array.</p>
    pub fn get_wireless_gateways(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.wireless_gateways
    }
    /// <p>The description of the new resource.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the new resource.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the new resource.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag to attach to the specified resource. Tags are metadata that you can use to manage a resource.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tag to attach to the specified resource. Tags are metadata that you can use to manage a resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag to attach to the specified resource. Tags are metadata that you can use to manage a resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Each resource must have a unique client request token. The client token is used to implement idempotency. It ensures that the request completes no more than one time. If you retry a request with the same token and the same parameters, the request will complete successfully. However, if you try to create a new resource using the same token but different parameters, an HTTP 409 conflict occurs. If you omit this value, AWS SDKs will automatically generate a unique client request. For more information about idempotency, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency in Amazon EC2 API requests</a>.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Each resource must have a unique client request token. The client token is used to implement idempotency. It ensures that the request completes no more than one time. If you retry a request with the same token and the same parameters, the request will complete successfully. However, if you try to create a new resource using the same token but different parameters, an HTTP 409 conflict occurs. If you omit this value, AWS SDKs will automatically generate a unique client request. For more information about idempotency, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency in Amazon EC2 API requests</a>.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Each resource must have a unique client request token. The client token is used to implement idempotency. It ensures that the request completes no more than one time. If you retry a request with the same token and the same parameters, the request will complete successfully. However, if you try to create a new resource using the same token but different parameters, an HTTP 409 conflict occurs. If you omit this value, AWS SDKs will automatically generate a unique client request. For more information about idempotency, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency in Amazon EC2 API requests</a>.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Appends an item to `multicast_groups`.
    ///
    /// To override the contents of this collection use [`set_multicast_groups`](Self::set_multicast_groups).
    ///
    /// <p>Multicast Group resources to add to the network analyzer configruation. Provide the <code>MulticastGroupId</code> of the resource to add in the input array.</p>
    pub fn multicast_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.multicast_groups.unwrap_or_default();
        v.push(input.into());
        self.multicast_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Multicast Group resources to add to the network analyzer configruation. Provide the <code>MulticastGroupId</code> of the resource to add in the input array.</p>
    pub fn set_multicast_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.multicast_groups = input;
        self
    }
    /// <p>Multicast Group resources to add to the network analyzer configruation. Provide the <code>MulticastGroupId</code> of the resource to add in the input array.</p>
    pub fn get_multicast_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.multicast_groups
    }
    /// Consumes the builder and constructs a [`CreateNetworkAnalyzerConfigurationInput`](crate::operation::create_network_analyzer_configuration::CreateNetworkAnalyzerConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_network_analyzer_configuration::CreateNetworkAnalyzerConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_network_analyzer_configuration::CreateNetworkAnalyzerConfigurationInput {
                name: self.name,
                trace_content: self.trace_content,
                wireless_devices: self.wireless_devices,
                wireless_gateways: self.wireless_gateways,
                description: self.description,
                tags: self.tags,
                client_request_token: self.client_request_token,
                multicast_groups: self.multicast_groups,
            },
        )
    }
}
