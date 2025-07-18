// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>BrokerNodeInfo</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BrokerNodeInfo {
    /// <p>The attached elastic network interface of the broker.</p>
    pub attached_eni_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the broker.</p>
    pub broker_id: ::std::option::Option<f64>,
    /// <p>The client subnet to which this broker node belongs.</p>
    pub client_subnet: ::std::option::Option<::std::string::String>,
    /// <p>The virtual private cloud (VPC) of the client.</p>
    pub client_vpc_ip_address: ::std::option::Option<::std::string::String>,
    /// <p>Information about the version of software currently deployed on the Apache Kafka brokers in the cluster.</p>
    pub current_broker_software_info: ::std::option::Option<crate::types::BrokerSoftwareInfo>,
    /// <p>Endpoints for accessing the broker.</p>
    pub endpoints: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BrokerNodeInfo {
    /// <p>The attached elastic network interface of the broker.</p>
    pub fn attached_eni_id(&self) -> ::std::option::Option<&str> {
        self.attached_eni_id.as_deref()
    }
    /// <p>The ID of the broker.</p>
    pub fn broker_id(&self) -> ::std::option::Option<f64> {
        self.broker_id
    }
    /// <p>The client subnet to which this broker node belongs.</p>
    pub fn client_subnet(&self) -> ::std::option::Option<&str> {
        self.client_subnet.as_deref()
    }
    /// <p>The virtual private cloud (VPC) of the client.</p>
    pub fn client_vpc_ip_address(&self) -> ::std::option::Option<&str> {
        self.client_vpc_ip_address.as_deref()
    }
    /// <p>Information about the version of software currently deployed on the Apache Kafka brokers in the cluster.</p>
    pub fn current_broker_software_info(&self) -> ::std::option::Option<&crate::types::BrokerSoftwareInfo> {
        self.current_broker_software_info.as_ref()
    }
    /// <p>Endpoints for accessing the broker.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoints.is_none()`.
    pub fn endpoints(&self) -> &[::std::string::String] {
        self.endpoints.as_deref().unwrap_or_default()
    }
}
impl BrokerNodeInfo {
    /// Creates a new builder-style object to manufacture [`BrokerNodeInfo`](crate::types::BrokerNodeInfo).
    pub fn builder() -> crate::types::builders::BrokerNodeInfoBuilder {
        crate::types::builders::BrokerNodeInfoBuilder::default()
    }
}

/// A builder for [`BrokerNodeInfo`](crate::types::BrokerNodeInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BrokerNodeInfoBuilder {
    pub(crate) attached_eni_id: ::std::option::Option<::std::string::String>,
    pub(crate) broker_id: ::std::option::Option<f64>,
    pub(crate) client_subnet: ::std::option::Option<::std::string::String>,
    pub(crate) client_vpc_ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) current_broker_software_info: ::std::option::Option<crate::types::BrokerSoftwareInfo>,
    pub(crate) endpoints: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BrokerNodeInfoBuilder {
    /// <p>The attached elastic network interface of the broker.</p>
    pub fn attached_eni_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attached_eni_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The attached elastic network interface of the broker.</p>
    pub fn set_attached_eni_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attached_eni_id = input;
        self
    }
    /// <p>The attached elastic network interface of the broker.</p>
    pub fn get_attached_eni_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.attached_eni_id
    }
    /// <p>The ID of the broker.</p>
    pub fn broker_id(mut self, input: f64) -> Self {
        self.broker_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the broker.</p>
    pub fn set_broker_id(mut self, input: ::std::option::Option<f64>) -> Self {
        self.broker_id = input;
        self
    }
    /// <p>The ID of the broker.</p>
    pub fn get_broker_id(&self) -> &::std::option::Option<f64> {
        &self.broker_id
    }
    /// <p>The client subnet to which this broker node belongs.</p>
    pub fn client_subnet(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_subnet = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client subnet to which this broker node belongs.</p>
    pub fn set_client_subnet(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_subnet = input;
        self
    }
    /// <p>The client subnet to which this broker node belongs.</p>
    pub fn get_client_subnet(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_subnet
    }
    /// <p>The virtual private cloud (VPC) of the client.</p>
    pub fn client_vpc_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_vpc_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The virtual private cloud (VPC) of the client.</p>
    pub fn set_client_vpc_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_vpc_ip_address = input;
        self
    }
    /// <p>The virtual private cloud (VPC) of the client.</p>
    pub fn get_client_vpc_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_vpc_ip_address
    }
    /// <p>Information about the version of software currently deployed on the Apache Kafka brokers in the cluster.</p>
    pub fn current_broker_software_info(mut self, input: crate::types::BrokerSoftwareInfo) -> Self {
        self.current_broker_software_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the version of software currently deployed on the Apache Kafka brokers in the cluster.</p>
    pub fn set_current_broker_software_info(mut self, input: ::std::option::Option<crate::types::BrokerSoftwareInfo>) -> Self {
        self.current_broker_software_info = input;
        self
    }
    /// <p>Information about the version of software currently deployed on the Apache Kafka brokers in the cluster.</p>
    pub fn get_current_broker_software_info(&self) -> &::std::option::Option<crate::types::BrokerSoftwareInfo> {
        &self.current_broker_software_info
    }
    /// Appends an item to `endpoints`.
    ///
    /// To override the contents of this collection use [`set_endpoints`](Self::set_endpoints).
    ///
    /// <p>Endpoints for accessing the broker.</p>
    pub fn endpoints(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.endpoints.unwrap_or_default();
        v.push(input.into());
        self.endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>Endpoints for accessing the broker.</p>
    pub fn set_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.endpoints = input;
        self
    }
    /// <p>Endpoints for accessing the broker.</p>
    pub fn get_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.endpoints
    }
    /// Consumes the builder and constructs a [`BrokerNodeInfo`](crate::types::BrokerNodeInfo).
    pub fn build(self) -> crate::types::BrokerNodeInfo {
        crate::types::BrokerNodeInfo {
            attached_eni_id: self.attached_eni_id,
            broker_id: self.broker_id,
            client_subnet: self.client_subnet,
            client_vpc_ip_address: self.client_vpc_ip_address,
            current_broker_software_info: self.current_broker_software_info,
            endpoints: self.endpoints,
        }
    }
}
