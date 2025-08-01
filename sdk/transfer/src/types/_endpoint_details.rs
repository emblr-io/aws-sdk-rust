// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The virtual private cloud (VPC) endpoint settings that are configured for your file transfer protocol-enabled server. With a VPC endpoint, you can restrict access to your server and resources only within your VPC. To control incoming internet traffic, invoke the <code>UpdateServer</code> API and attach an Elastic IP address to your server's endpoint.</p><note>
/// <p>After May 19, 2021, you won't be able to create a server using <code>EndpointType=VPC_ENDPOINT</code> in your Amazon Web Services account if your account hasn't already done so before May 19, 2021. If you have already created servers with <code>EndpointType=VPC_ENDPOINT</code> in your Amazon Web Services account on or before May 19, 2021, you will not be affected. After this date, use <code>EndpointType</code>=<code>VPC</code>.</p>
/// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
/// <p>It is recommended that you use <code>VPC</code> as the <code>EndpointType</code>. With this endpoint type, you have the option to directly associate up to three Elastic IPv4 addresses (BYO IP included) with your server's endpoint and use VPC security groups to restrict traffic by the client's public IP address. This is not possible with <code>EndpointType</code> set to <code>VPC_ENDPOINT</code>.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EndpointDetails {
    /// <p>A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.</p>
    /// <p>An address allocation ID corresponds to the allocation ID of an Elastic IP address. This value can be retrieved from the <code>allocationId</code> field from the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html">Address</a> data type. One way to retrieve this value is by calling the EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html">DescribeAddresses</a> API.</p>
    /// <p>This parameter is optional. Set this parameter if you want to make your VPC endpoint public-facing. For details, see <a href="https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#create-internet-facing-endpoint">Create an internet-facing endpoint for your server</a>.</p><note>
    /// <p>This property can only be set as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>EndpointType</code> must be set to <code>VPC</code></p></li>
    /// <li>
    /// <p>The Transfer Family server must be offline.</p></li>
    /// <li>
    /// <p>You cannot set this parameter for Transfer Family servers that use the FTP protocol.</p></li>
    /// <li>
    /// <p>The server must already have <code>SubnetIds</code> populated (<code>SubnetIds</code> and <code>AddressAllocationIds</code> cannot be updated simultaneously).</p></li>
    /// <li>
    /// <p><code>AddressAllocationIds</code> can't contain duplicates, and must be equal in length to <code>SubnetIds</code>. For example, if you have three subnet IDs, you must also specify three address allocation IDs.</p></li>
    /// <li>
    /// <p>Call the <code>UpdateServer</code> API to set or change this parameter.</p></li>
    /// <li>
    /// <p>You can't set address allocation IDs for servers that have an <code>IpAddressType</code> set to <code>DUALSTACK</code> You can only set this property if <code>IpAddressType</code> is set to <code>IPV4</code>.</p></li>
    /// </ul>
    /// </note>
    pub address_allocation_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of subnet IDs that are required to host your server endpoint in your VPC.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The identifier of the VPC endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC_ENDPOINT</code>.</p>
    /// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
    /// </note>
    pub vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The VPC identifier of the VPC in which a server's endpoint will be hosted.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of security groups IDs that are available to attach to your server's endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// <p>You can edit the <code>SecurityGroupIds</code> property in the <a href="https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html">UpdateServer</a> API only if you are changing the <code>EndpointType</code> from <code>PUBLIC</code> or <code>VPC_ENDPOINT</code> to <code>VPC</code>. To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html">ModifyVpcEndpoint</a> API.</p>
    /// </note>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EndpointDetails {
    /// <p>A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.</p>
    /// <p>An address allocation ID corresponds to the allocation ID of an Elastic IP address. This value can be retrieved from the <code>allocationId</code> field from the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html">Address</a> data type. One way to retrieve this value is by calling the EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html">DescribeAddresses</a> API.</p>
    /// <p>This parameter is optional. Set this parameter if you want to make your VPC endpoint public-facing. For details, see <a href="https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#create-internet-facing-endpoint">Create an internet-facing endpoint for your server</a>.</p><note>
    /// <p>This property can only be set as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>EndpointType</code> must be set to <code>VPC</code></p></li>
    /// <li>
    /// <p>The Transfer Family server must be offline.</p></li>
    /// <li>
    /// <p>You cannot set this parameter for Transfer Family servers that use the FTP protocol.</p></li>
    /// <li>
    /// <p>The server must already have <code>SubnetIds</code> populated (<code>SubnetIds</code> and <code>AddressAllocationIds</code> cannot be updated simultaneously).</p></li>
    /// <li>
    /// <p><code>AddressAllocationIds</code> can't contain duplicates, and must be equal in length to <code>SubnetIds</code>. For example, if you have three subnet IDs, you must also specify three address allocation IDs.</p></li>
    /// <li>
    /// <p>Call the <code>UpdateServer</code> API to set or change this parameter.</p></li>
    /// <li>
    /// <p>You can't set address allocation IDs for servers that have an <code>IpAddressType</code> set to <code>DUALSTACK</code> You can only set this property if <code>IpAddressType</code> is set to <code>IPV4</code>.</p></li>
    /// </ul>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.address_allocation_ids.is_none()`.
    pub fn address_allocation_ids(&self) -> &[::std::string::String] {
        self.address_allocation_ids.as_deref().unwrap_or_default()
    }
    /// <p>A list of subnet IDs that are required to host your server endpoint in your VPC.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of the VPC endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC_ENDPOINT</code>.</p>
    /// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
    /// </note>
    pub fn vpc_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_id.as_deref()
    }
    /// <p>The VPC identifier of the VPC in which a server's endpoint will be hosted.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>A list of security groups IDs that are available to attach to your server's endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// <p>You can edit the <code>SecurityGroupIds</code> property in the <a href="https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html">UpdateServer</a> API only if you are changing the <code>EndpointType</code> from <code>PUBLIC</code> or <code>VPC_ENDPOINT</code> to <code>VPC</code>. To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html">ModifyVpcEndpoint</a> API.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
}
impl EndpointDetails {
    /// Creates a new builder-style object to manufacture [`EndpointDetails`](crate::types::EndpointDetails).
    pub fn builder() -> crate::types::builders::EndpointDetailsBuilder {
        crate::types::builders::EndpointDetailsBuilder::default()
    }
}

/// A builder for [`EndpointDetails`](crate::types::EndpointDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointDetailsBuilder {
    pub(crate) address_allocation_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EndpointDetailsBuilder {
    /// Appends an item to `address_allocation_ids`.
    ///
    /// To override the contents of this collection use [`set_address_allocation_ids`](Self::set_address_allocation_ids).
    ///
    /// <p>A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.</p>
    /// <p>An address allocation ID corresponds to the allocation ID of an Elastic IP address. This value can be retrieved from the <code>allocationId</code> field from the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html">Address</a> data type. One way to retrieve this value is by calling the EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html">DescribeAddresses</a> API.</p>
    /// <p>This parameter is optional. Set this parameter if you want to make your VPC endpoint public-facing. For details, see <a href="https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#create-internet-facing-endpoint">Create an internet-facing endpoint for your server</a>.</p><note>
    /// <p>This property can only be set as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>EndpointType</code> must be set to <code>VPC</code></p></li>
    /// <li>
    /// <p>The Transfer Family server must be offline.</p></li>
    /// <li>
    /// <p>You cannot set this parameter for Transfer Family servers that use the FTP protocol.</p></li>
    /// <li>
    /// <p>The server must already have <code>SubnetIds</code> populated (<code>SubnetIds</code> and <code>AddressAllocationIds</code> cannot be updated simultaneously).</p></li>
    /// <li>
    /// <p><code>AddressAllocationIds</code> can't contain duplicates, and must be equal in length to <code>SubnetIds</code>. For example, if you have three subnet IDs, you must also specify three address allocation IDs.</p></li>
    /// <li>
    /// <p>Call the <code>UpdateServer</code> API to set or change this parameter.</p></li>
    /// <li>
    /// <p>You can't set address allocation IDs for servers that have an <code>IpAddressType</code> set to <code>DUALSTACK</code> You can only set this property if <code>IpAddressType</code> is set to <code>IPV4</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn address_allocation_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.address_allocation_ids.unwrap_or_default();
        v.push(input.into());
        self.address_allocation_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.</p>
    /// <p>An address allocation ID corresponds to the allocation ID of an Elastic IP address. This value can be retrieved from the <code>allocationId</code> field from the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html">Address</a> data type. One way to retrieve this value is by calling the EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html">DescribeAddresses</a> API.</p>
    /// <p>This parameter is optional. Set this parameter if you want to make your VPC endpoint public-facing. For details, see <a href="https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#create-internet-facing-endpoint">Create an internet-facing endpoint for your server</a>.</p><note>
    /// <p>This property can only be set as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>EndpointType</code> must be set to <code>VPC</code></p></li>
    /// <li>
    /// <p>The Transfer Family server must be offline.</p></li>
    /// <li>
    /// <p>You cannot set this parameter for Transfer Family servers that use the FTP protocol.</p></li>
    /// <li>
    /// <p>The server must already have <code>SubnetIds</code> populated (<code>SubnetIds</code> and <code>AddressAllocationIds</code> cannot be updated simultaneously).</p></li>
    /// <li>
    /// <p><code>AddressAllocationIds</code> can't contain duplicates, and must be equal in length to <code>SubnetIds</code>. For example, if you have three subnet IDs, you must also specify three address allocation IDs.</p></li>
    /// <li>
    /// <p>Call the <code>UpdateServer</code> API to set or change this parameter.</p></li>
    /// <li>
    /// <p>You can't set address allocation IDs for servers that have an <code>IpAddressType</code> set to <code>DUALSTACK</code> You can only set this property if <code>IpAddressType</code> is set to <code>IPV4</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn set_address_allocation_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.address_allocation_ids = input;
        self
    }
    /// <p>A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.</p>
    /// <p>An address allocation ID corresponds to the allocation ID of an Elastic IP address. This value can be retrieved from the <code>allocationId</code> field from the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html">Address</a> data type. One way to retrieve this value is by calling the EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html">DescribeAddresses</a> API.</p>
    /// <p>This parameter is optional. Set this parameter if you want to make your VPC endpoint public-facing. For details, see <a href="https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#create-internet-facing-endpoint">Create an internet-facing endpoint for your server</a>.</p><note>
    /// <p>This property can only be set as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>EndpointType</code> must be set to <code>VPC</code></p></li>
    /// <li>
    /// <p>The Transfer Family server must be offline.</p></li>
    /// <li>
    /// <p>You cannot set this parameter for Transfer Family servers that use the FTP protocol.</p></li>
    /// <li>
    /// <p>The server must already have <code>SubnetIds</code> populated (<code>SubnetIds</code> and <code>AddressAllocationIds</code> cannot be updated simultaneously).</p></li>
    /// <li>
    /// <p><code>AddressAllocationIds</code> can't contain duplicates, and must be equal in length to <code>SubnetIds</code>. For example, if you have three subnet IDs, you must also specify three address allocation IDs.</p></li>
    /// <li>
    /// <p>Call the <code>UpdateServer</code> API to set or change this parameter.</p></li>
    /// <li>
    /// <p>You can't set address allocation IDs for servers that have an <code>IpAddressType</code> set to <code>DUALSTACK</code> You can only set this property if <code>IpAddressType</code> is set to <code>IPV4</code>.</p></li>
    /// </ul>
    /// </note>
    pub fn get_address_allocation_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.address_allocation_ids
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>A list of subnet IDs that are required to host your server endpoint in your VPC.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of subnet IDs that are required to host your server endpoint in your VPC.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>A list of subnet IDs that are required to host your server endpoint in your VPC.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// <p>The identifier of the VPC endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC_ENDPOINT</code>.</p>
    /// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
    /// </note>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the VPC endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC_ENDPOINT</code>.</p>
    /// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
    /// </note>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_id = input;
        self
    }
    /// <p>The identifier of the VPC endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC_ENDPOINT</code>.</p>
    /// <p>For more information, see https://docs.aws.amazon.com/transfer/latest/userguide/create-server-in-vpc.html#deprecate-vpc-endpoint.</p>
    /// </note>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_id
    }
    /// <p>The VPC identifier of the VPC in which a server's endpoint will be hosted.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC identifier of the VPC in which a server's endpoint will be hosted.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The VPC identifier of the VPC in which a server's endpoint will be hosted.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// </note>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>A list of security groups IDs that are available to attach to your server's endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// <p>You can edit the <code>SecurityGroupIds</code> property in the <a href="https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html">UpdateServer</a> API only if you are changing the <code>EndpointType</code> from <code>PUBLIC</code> or <code>VPC_ENDPOINT</code> to <code>VPC</code>. To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html">ModifyVpcEndpoint</a> API.</p>
    /// </note>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of security groups IDs that are available to attach to your server's endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// <p>You can edit the <code>SecurityGroupIds</code> property in the <a href="https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html">UpdateServer</a> API only if you are changing the <code>EndpointType</code> from <code>PUBLIC</code> or <code>VPC_ENDPOINT</code> to <code>VPC</code>. To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html">ModifyVpcEndpoint</a> API.</p>
    /// </note>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>A list of security groups IDs that are available to attach to your server's endpoint.</p><note>
    /// <p>This property can only be set when <code>EndpointType</code> is set to <code>VPC</code>.</p>
    /// <p>You can edit the <code>SecurityGroupIds</code> property in the <a href="https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html">UpdateServer</a> API only if you are changing the <code>EndpointType</code> from <code>PUBLIC</code> or <code>VPC_ENDPOINT</code> to <code>VPC</code>. To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 <a href="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html">ModifyVpcEndpoint</a> API.</p>
    /// </note>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// Consumes the builder and constructs a [`EndpointDetails`](crate::types::EndpointDetails).
    pub fn build(self) -> crate::types::EndpointDetails {
        crate::types::EndpointDetails {
            address_allocation_ids: self.address_allocation_ids,
            subnet_ids: self.subnet_ids,
            vpc_endpoint_id: self.vpc_endpoint_id,
            vpc_id: self.vpc_id,
            security_group_ids: self.security_group_ids,
        }
    }
}
