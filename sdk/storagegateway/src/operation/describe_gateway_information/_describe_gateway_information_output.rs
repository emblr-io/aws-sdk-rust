// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON object containing the following fields:</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGatewayInformationOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier assigned to your gateway during activation. This ID becomes part of the gateway Amazon Resource Name (ARN), which you use as input for other operations.</p>
    pub gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>The name you configured for your gateway.</p>
    pub gateway_name: ::std::option::Option<::std::string::String>,
    /// <p>A value that indicates the time zone configured for the gateway.</p>
    pub gateway_timezone: ::std::option::Option<::std::string::String>,
    /// <p>A value that indicates the operating state of the gateway.</p>
    pub gateway_state: ::std::option::Option<::std::string::String>,
    /// <p>A <code>NetworkInterface</code> array that contains descriptions of the gateway network interfaces.</p>
    pub gateway_network_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>,
    /// <p>The type of the gateway.</p><important>
    /// <p>Amazon FSx File Gateway is no longer available to new customers. Existing customers of FSx File Gateway can continue to use the service normally. For capabilities similar to FSx File Gateway, visit <a href="https://aws.amazon.com/blogs/storage/switch-your-file-share-access-from-amazon-fsx-file-gateway-to-amazon-fsx-for-windows-file-server/">this blog post</a>.</p>
    /// </important>
    pub gateway_type: ::std::option::Option<::std::string::String>,
    /// <p>The date on which an update to the gateway is available. This date is in the time zone of the gateway. If the gateway is not available for an update this field is not returned in the response.</p>
    pub next_update_availability_date: ::std::option::Option<::std::string::String>,
    /// <p>The date on which the last software update was applied to the gateway. If the gateway has never been updated, this field does not return a value in the response. This only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub last_software_update: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon EC2 instance that was used to launch the gateway.</p>
    pub ec2_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services Region where the Amazon EC2 instance is located.</p>
    pub ec2_instance_region: ::std::option::Option<::std::string::String>,
    /// <p>A list of up to 50 tags assigned to the gateway, sorted alphabetically by key name. Each tag is a key-value pair. For a gateway with more than 10 tags assigned, you can view all tags using the <code>ListTagsForResource</code> API operation.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The configuration settings for the virtual private cloud (VPC) endpoint for your gateway.</p>
    pub vpc_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Amazon CloudWatch log group that is used to monitor events in the gateway. This field only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub cloud_watch_log_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of hardware or software platform on which the gateway is running.</p><note>
    /// <p>Tape Gateway is no longer available on Snow Family devices.</p>
    /// </note>
    pub host_environment: ::std::option::Option<crate::types::HostEnvironment>,
    /// <p>The type of endpoint for your gateway.</p>
    /// <p>Valid Values: <code>STANDARD</code> | <code>FIPS</code></p>
    pub endpoint_type: ::std::option::Option<::std::string::String>,
    /// <p>Date after which this gateway will not receive software updates for new features.</p>
    pub software_updates_end_date: ::std::option::Option<::std::string::String>,
    /// <p>Date after which this gateway will not receive software updates for new features and bug fixes.</p>
    pub deprecation_date: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the size of the gateway's metadata cache.</p>
    pub gateway_capacity: ::std::option::Option<crate::types::GatewayCapacity>,
    /// <p>A list of the metadata cache sizes that the gateway can support based on its current hardware specifications.</p>
    pub supported_gateway_capacities: ::std::option::Option<::std::vec::Vec<crate::types::GatewayCapacity>>,
    /// <p>A unique identifier for the specific instance of the host platform running the gateway. This value is only available for certain host environments, and its format depends on the host environment type.</p>
    pub host_environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the software running on the gateway appliance.</p>
    pub software_version: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGatewayInformationOutput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The unique identifier assigned to your gateway during activation. This ID becomes part of the gateway Amazon Resource Name (ARN), which you use as input for other operations.</p>
    pub fn gateway_id(&self) -> ::std::option::Option<&str> {
        self.gateway_id.as_deref()
    }
    /// <p>The name you configured for your gateway.</p>
    pub fn gateway_name(&self) -> ::std::option::Option<&str> {
        self.gateway_name.as_deref()
    }
    /// <p>A value that indicates the time zone configured for the gateway.</p>
    pub fn gateway_timezone(&self) -> ::std::option::Option<&str> {
        self.gateway_timezone.as_deref()
    }
    /// <p>A value that indicates the operating state of the gateway.</p>
    pub fn gateway_state(&self) -> ::std::option::Option<&str> {
        self.gateway_state.as_deref()
    }
    /// <p>A <code>NetworkInterface</code> array that contains descriptions of the gateway network interfaces.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.gateway_network_interfaces.is_none()`.
    pub fn gateway_network_interfaces(&self) -> &[crate::types::NetworkInterface] {
        self.gateway_network_interfaces.as_deref().unwrap_or_default()
    }
    /// <p>The type of the gateway.</p><important>
    /// <p>Amazon FSx File Gateway is no longer available to new customers. Existing customers of FSx File Gateway can continue to use the service normally. For capabilities similar to FSx File Gateway, visit <a href="https://aws.amazon.com/blogs/storage/switch-your-file-share-access-from-amazon-fsx-file-gateway-to-amazon-fsx-for-windows-file-server/">this blog post</a>.</p>
    /// </important>
    pub fn gateway_type(&self) -> ::std::option::Option<&str> {
        self.gateway_type.as_deref()
    }
    /// <p>The date on which an update to the gateway is available. This date is in the time zone of the gateway. If the gateway is not available for an update this field is not returned in the response.</p>
    pub fn next_update_availability_date(&self) -> ::std::option::Option<&str> {
        self.next_update_availability_date.as_deref()
    }
    /// <p>The date on which the last software update was applied to the gateway. If the gateway has never been updated, this field does not return a value in the response. This only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn last_software_update(&self) -> ::std::option::Option<&str> {
        self.last_software_update.as_deref()
    }
    /// <p>The ID of the Amazon EC2 instance that was used to launch the gateway.</p>
    pub fn ec2_instance_id(&self) -> ::std::option::Option<&str> {
        self.ec2_instance_id.as_deref()
    }
    /// <p>The Amazon Web Services Region where the Amazon EC2 instance is located.</p>
    pub fn ec2_instance_region(&self) -> ::std::option::Option<&str> {
        self.ec2_instance_region.as_deref()
    }
    /// <p>A list of up to 50 tags assigned to the gateway, sorted alphabetically by key name. Each tag is a key-value pair. For a gateway with more than 10 tags assigned, you can view all tags using the <code>ListTagsForResource</code> API operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The configuration settings for the virtual private cloud (VPC) endpoint for your gateway.</p>
    pub fn vpc_endpoint(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon CloudWatch log group that is used to monitor events in the gateway. This field only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn cloud_watch_log_group_arn(&self) -> ::std::option::Option<&str> {
        self.cloud_watch_log_group_arn.as_deref()
    }
    /// <p>The type of hardware or software platform on which the gateway is running.</p><note>
    /// <p>Tape Gateway is no longer available on Snow Family devices.</p>
    /// </note>
    pub fn host_environment(&self) -> ::std::option::Option<&crate::types::HostEnvironment> {
        self.host_environment.as_ref()
    }
    /// <p>The type of endpoint for your gateway.</p>
    /// <p>Valid Values: <code>STANDARD</code> | <code>FIPS</code></p>
    pub fn endpoint_type(&self) -> ::std::option::Option<&str> {
        self.endpoint_type.as_deref()
    }
    /// <p>Date after which this gateway will not receive software updates for new features.</p>
    pub fn software_updates_end_date(&self) -> ::std::option::Option<&str> {
        self.software_updates_end_date.as_deref()
    }
    /// <p>Date after which this gateway will not receive software updates for new features and bug fixes.</p>
    pub fn deprecation_date(&self) -> ::std::option::Option<&str> {
        self.deprecation_date.as_deref()
    }
    /// <p>Specifies the size of the gateway's metadata cache.</p>
    pub fn gateway_capacity(&self) -> ::std::option::Option<&crate::types::GatewayCapacity> {
        self.gateway_capacity.as_ref()
    }
    /// <p>A list of the metadata cache sizes that the gateway can support based on its current hardware specifications.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_gateway_capacities.is_none()`.
    pub fn supported_gateway_capacities(&self) -> &[crate::types::GatewayCapacity] {
        self.supported_gateway_capacities.as_deref().unwrap_or_default()
    }
    /// <p>A unique identifier for the specific instance of the host platform running the gateway. This value is only available for certain host environments, and its format depends on the host environment type.</p>
    pub fn host_environment_id(&self) -> ::std::option::Option<&str> {
        self.host_environment_id.as_deref()
    }
    /// <p>The version number of the software running on the gateway appliance.</p>
    pub fn software_version(&self) -> ::std::option::Option<&str> {
        self.software_version.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeGatewayInformationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeGatewayInformationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeGatewayInformationOutput`](crate::operation::describe_gateway_information::DescribeGatewayInformationOutput).
    pub fn builder() -> crate::operation::describe_gateway_information::builders::DescribeGatewayInformationOutputBuilder {
        crate::operation::describe_gateway_information::builders::DescribeGatewayInformationOutputBuilder::default()
    }
}

/// A builder for [`DescribeGatewayInformationOutput`](crate::operation::describe_gateway_information::DescribeGatewayInformationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGatewayInformationOutputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_name: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_timezone: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_state: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_network_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>,
    pub(crate) gateway_type: ::std::option::Option<::std::string::String>,
    pub(crate) next_update_availability_date: ::std::option::Option<::std::string::String>,
    pub(crate) last_software_update: ::std::option::Option<::std::string::String>,
    pub(crate) ec2_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) ec2_instance_region: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) vpc_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) cloud_watch_log_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) host_environment: ::std::option::Option<crate::types::HostEnvironment>,
    pub(crate) endpoint_type: ::std::option::Option<::std::string::String>,
    pub(crate) software_updates_end_date: ::std::option::Option<::std::string::String>,
    pub(crate) deprecation_date: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_capacity: ::std::option::Option<crate::types::GatewayCapacity>,
    pub(crate) supported_gateway_capacities: ::std::option::Option<::std::vec::Vec<crate::types::GatewayCapacity>>,
    pub(crate) host_environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) software_version: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGatewayInformationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// <p>The unique identifier assigned to your gateway during activation. This ID becomes part of the gateway Amazon Resource Name (ARN), which you use as input for other operations.</p>
    pub fn gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier assigned to your gateway during activation. This ID becomes part of the gateway Amazon Resource Name (ARN), which you use as input for other operations.</p>
    pub fn set_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_id = input;
        self
    }
    /// <p>The unique identifier assigned to your gateway during activation. This ID becomes part of the gateway Amazon Resource Name (ARN), which you use as input for other operations.</p>
    pub fn get_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_id
    }
    /// <p>The name you configured for your gateway.</p>
    pub fn gateway_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name you configured for your gateway.</p>
    pub fn set_gateway_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_name = input;
        self
    }
    /// <p>The name you configured for your gateway.</p>
    pub fn get_gateway_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_name
    }
    /// <p>A value that indicates the time zone configured for the gateway.</p>
    pub fn gateway_timezone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_timezone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the time zone configured for the gateway.</p>
    pub fn set_gateway_timezone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_timezone = input;
        self
    }
    /// <p>A value that indicates the time zone configured for the gateway.</p>
    pub fn get_gateway_timezone(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_timezone
    }
    /// <p>A value that indicates the operating state of the gateway.</p>
    pub fn gateway_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that indicates the operating state of the gateway.</p>
    pub fn set_gateway_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_state = input;
        self
    }
    /// <p>A value that indicates the operating state of the gateway.</p>
    pub fn get_gateway_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_state
    }
    /// Appends an item to `gateway_network_interfaces`.
    ///
    /// To override the contents of this collection use [`set_gateway_network_interfaces`](Self::set_gateway_network_interfaces).
    ///
    /// <p>A <code>NetworkInterface</code> array that contains descriptions of the gateway network interfaces.</p>
    pub fn gateway_network_interfaces(mut self, input: crate::types::NetworkInterface) -> Self {
        let mut v = self.gateway_network_interfaces.unwrap_or_default();
        v.push(input);
        self.gateway_network_interfaces = ::std::option::Option::Some(v);
        self
    }
    /// <p>A <code>NetworkInterface</code> array that contains descriptions of the gateway network interfaces.</p>
    pub fn set_gateway_network_interfaces(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>) -> Self {
        self.gateway_network_interfaces = input;
        self
    }
    /// <p>A <code>NetworkInterface</code> array that contains descriptions of the gateway network interfaces.</p>
    pub fn get_gateway_network_interfaces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>> {
        &self.gateway_network_interfaces
    }
    /// <p>The type of the gateway.</p><important>
    /// <p>Amazon FSx File Gateway is no longer available to new customers. Existing customers of FSx File Gateway can continue to use the service normally. For capabilities similar to FSx File Gateway, visit <a href="https://aws.amazon.com/blogs/storage/switch-your-file-share-access-from-amazon-fsx-file-gateway-to-amazon-fsx-for-windows-file-server/">this blog post</a>.</p>
    /// </important>
    pub fn gateway_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the gateway.</p><important>
    /// <p>Amazon FSx File Gateway is no longer available to new customers. Existing customers of FSx File Gateway can continue to use the service normally. For capabilities similar to FSx File Gateway, visit <a href="https://aws.amazon.com/blogs/storage/switch-your-file-share-access-from-amazon-fsx-file-gateway-to-amazon-fsx-for-windows-file-server/">this blog post</a>.</p>
    /// </important>
    pub fn set_gateway_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_type = input;
        self
    }
    /// <p>The type of the gateway.</p><important>
    /// <p>Amazon FSx File Gateway is no longer available to new customers. Existing customers of FSx File Gateway can continue to use the service normally. For capabilities similar to FSx File Gateway, visit <a href="https://aws.amazon.com/blogs/storage/switch-your-file-share-access-from-amazon-fsx-file-gateway-to-amazon-fsx-for-windows-file-server/">this blog post</a>.</p>
    /// </important>
    pub fn get_gateway_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_type
    }
    /// <p>The date on which an update to the gateway is available. This date is in the time zone of the gateway. If the gateway is not available for an update this field is not returned in the response.</p>
    pub fn next_update_availability_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_update_availability_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which an update to the gateway is available. This date is in the time zone of the gateway. If the gateway is not available for an update this field is not returned in the response.</p>
    pub fn set_next_update_availability_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_update_availability_date = input;
        self
    }
    /// <p>The date on which an update to the gateway is available. This date is in the time zone of the gateway. If the gateway is not available for an update this field is not returned in the response.</p>
    pub fn get_next_update_availability_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_update_availability_date
    }
    /// <p>The date on which the last software update was applied to the gateway. If the gateway has never been updated, this field does not return a value in the response. This only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn last_software_update(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_software_update = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date on which the last software update was applied to the gateway. If the gateway has never been updated, this field does not return a value in the response. This only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn set_last_software_update(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_software_update = input;
        self
    }
    /// <p>The date on which the last software update was applied to the gateway. If the gateway has never been updated, this field does not return a value in the response. This only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn get_last_software_update(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_software_update
    }
    /// <p>The ID of the Amazon EC2 instance that was used to launch the gateway.</p>
    pub fn ec2_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ec2_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon EC2 instance that was used to launch the gateway.</p>
    pub fn set_ec2_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ec2_instance_id = input;
        self
    }
    /// <p>The ID of the Amazon EC2 instance that was used to launch the gateway.</p>
    pub fn get_ec2_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ec2_instance_id
    }
    /// <p>The Amazon Web Services Region where the Amazon EC2 instance is located.</p>
    pub fn ec2_instance_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ec2_instance_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region where the Amazon EC2 instance is located.</p>
    pub fn set_ec2_instance_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ec2_instance_region = input;
        self
    }
    /// <p>The Amazon Web Services Region where the Amazon EC2 instance is located.</p>
    pub fn get_ec2_instance_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.ec2_instance_region
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of up to 50 tags assigned to the gateway, sorted alphabetically by key name. Each tag is a key-value pair. For a gateway with more than 10 tags assigned, you can view all tags using the <code>ListTagsForResource</code> API operation.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of up to 50 tags assigned to the gateway, sorted alphabetically by key name. Each tag is a key-value pair. For a gateway with more than 10 tags assigned, you can view all tags using the <code>ListTagsForResource</code> API operation.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of up to 50 tags assigned to the gateway, sorted alphabetically by key name. Each tag is a key-value pair. For a gateway with more than 10 tags assigned, you can view all tags using the <code>ListTagsForResource</code> API operation.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The configuration settings for the virtual private cloud (VPC) endpoint for your gateway.</p>
    pub fn vpc_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration settings for the virtual private cloud (VPC) endpoint for your gateway.</p>
    pub fn set_vpc_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint = input;
        self
    }
    /// <p>The configuration settings for the virtual private cloud (VPC) endpoint for your gateway.</p>
    pub fn get_vpc_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon CloudWatch log group that is used to monitor events in the gateway. This field only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn cloud_watch_log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_watch_log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon CloudWatch log group that is used to monitor events in the gateway. This field only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn set_cloud_watch_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_watch_log_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon CloudWatch log group that is used to monitor events in the gateway. This field only only exist and returns once it have been chosen and set by the SGW service, based on the OS version of the gateway VM</p>
    pub fn get_cloud_watch_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_watch_log_group_arn
    }
    /// <p>The type of hardware or software platform on which the gateway is running.</p><note>
    /// <p>Tape Gateway is no longer available on Snow Family devices.</p>
    /// </note>
    pub fn host_environment(mut self, input: crate::types::HostEnvironment) -> Self {
        self.host_environment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of hardware or software platform on which the gateway is running.</p><note>
    /// <p>Tape Gateway is no longer available on Snow Family devices.</p>
    /// </note>
    pub fn set_host_environment(mut self, input: ::std::option::Option<crate::types::HostEnvironment>) -> Self {
        self.host_environment = input;
        self
    }
    /// <p>The type of hardware or software platform on which the gateway is running.</p><note>
    /// <p>Tape Gateway is no longer available on Snow Family devices.</p>
    /// </note>
    pub fn get_host_environment(&self) -> &::std::option::Option<crate::types::HostEnvironment> {
        &self.host_environment
    }
    /// <p>The type of endpoint for your gateway.</p>
    /// <p>Valid Values: <code>STANDARD</code> | <code>FIPS</code></p>
    pub fn endpoint_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of endpoint for your gateway.</p>
    /// <p>Valid Values: <code>STANDARD</code> | <code>FIPS</code></p>
    pub fn set_endpoint_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_type = input;
        self
    }
    /// <p>The type of endpoint for your gateway.</p>
    /// <p>Valid Values: <code>STANDARD</code> | <code>FIPS</code></p>
    pub fn get_endpoint_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_type
    }
    /// <p>Date after which this gateway will not receive software updates for new features.</p>
    pub fn software_updates_end_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.software_updates_end_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Date after which this gateway will not receive software updates for new features.</p>
    pub fn set_software_updates_end_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.software_updates_end_date = input;
        self
    }
    /// <p>Date after which this gateway will not receive software updates for new features.</p>
    pub fn get_software_updates_end_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.software_updates_end_date
    }
    /// <p>Date after which this gateway will not receive software updates for new features and bug fixes.</p>
    pub fn deprecation_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deprecation_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Date after which this gateway will not receive software updates for new features and bug fixes.</p>
    pub fn set_deprecation_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deprecation_date = input;
        self
    }
    /// <p>Date after which this gateway will not receive software updates for new features and bug fixes.</p>
    pub fn get_deprecation_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.deprecation_date
    }
    /// <p>Specifies the size of the gateway's metadata cache.</p>
    pub fn gateway_capacity(mut self, input: crate::types::GatewayCapacity) -> Self {
        self.gateway_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the size of the gateway's metadata cache.</p>
    pub fn set_gateway_capacity(mut self, input: ::std::option::Option<crate::types::GatewayCapacity>) -> Self {
        self.gateway_capacity = input;
        self
    }
    /// <p>Specifies the size of the gateway's metadata cache.</p>
    pub fn get_gateway_capacity(&self) -> &::std::option::Option<crate::types::GatewayCapacity> {
        &self.gateway_capacity
    }
    /// Appends an item to `supported_gateway_capacities`.
    ///
    /// To override the contents of this collection use [`set_supported_gateway_capacities`](Self::set_supported_gateway_capacities).
    ///
    /// <p>A list of the metadata cache sizes that the gateway can support based on its current hardware specifications.</p>
    pub fn supported_gateway_capacities(mut self, input: crate::types::GatewayCapacity) -> Self {
        let mut v = self.supported_gateway_capacities.unwrap_or_default();
        v.push(input);
        self.supported_gateway_capacities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the metadata cache sizes that the gateway can support based on its current hardware specifications.</p>
    pub fn set_supported_gateway_capacities(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GatewayCapacity>>) -> Self {
        self.supported_gateway_capacities = input;
        self
    }
    /// <p>A list of the metadata cache sizes that the gateway can support based on its current hardware specifications.</p>
    pub fn get_supported_gateway_capacities(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GatewayCapacity>> {
        &self.supported_gateway_capacities
    }
    /// <p>A unique identifier for the specific instance of the host platform running the gateway. This value is only available for certain host environments, and its format depends on the host environment type.</p>
    pub fn host_environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host_environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the specific instance of the host platform running the gateway. This value is only available for certain host environments, and its format depends on the host environment type.</p>
    pub fn set_host_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host_environment_id = input;
        self
    }
    /// <p>A unique identifier for the specific instance of the host platform running the gateway. This value is only available for certain host environments, and its format depends on the host environment type.</p>
    pub fn get_host_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.host_environment_id
    }
    /// <p>The version number of the software running on the gateway appliance.</p>
    pub fn software_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.software_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of the software running on the gateway appliance.</p>
    pub fn set_software_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.software_version = input;
        self
    }
    /// <p>The version number of the software running on the gateway appliance.</p>
    pub fn get_software_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.software_version
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeGatewayInformationOutput`](crate::operation::describe_gateway_information::DescribeGatewayInformationOutput).
    pub fn build(self) -> crate::operation::describe_gateway_information::DescribeGatewayInformationOutput {
        crate::operation::describe_gateway_information::DescribeGatewayInformationOutput {
            gateway_arn: self.gateway_arn,
            gateway_id: self.gateway_id,
            gateway_name: self.gateway_name,
            gateway_timezone: self.gateway_timezone,
            gateway_state: self.gateway_state,
            gateway_network_interfaces: self.gateway_network_interfaces,
            gateway_type: self.gateway_type,
            next_update_availability_date: self.next_update_availability_date,
            last_software_update: self.last_software_update,
            ec2_instance_id: self.ec2_instance_id,
            ec2_instance_region: self.ec2_instance_region,
            tags: self.tags,
            vpc_endpoint: self.vpc_endpoint,
            cloud_watch_log_group_arn: self.cloud_watch_log_group_arn,
            host_environment: self.host_environment,
            endpoint_type: self.endpoint_type,
            software_updates_end_date: self.software_updates_end_date,
            deprecation_date: self.deprecation_date,
            gateway_capacity: self.gateway_capacity,
            supported_gateway_capacities: self.supported_gateway_capacities,
            host_environment_id: self.host_environment_id,
            software_version: self.software_version,
            _request_id: self._request_id,
        }
    }
}
