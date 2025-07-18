// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A gateway is an Backup Gateway appliance that runs on the customer's network to provide seamless connectivity to backup storage in the Amazon Web Services Cloud.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Gateway {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the gateway.</p>
    pub gateway_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the gateway.</p>
    pub gateway_type: ::std::option::Option<crate::types::GatewayType>,
    /// <p>The hypervisor ID of the gateway.</p>
    pub hypervisor_id: ::std::option::Option<::std::string::String>,
    /// <p>The last time Backup gateway communicated with the gateway, in Unix format and UTC time.</p>
    pub last_seen_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl Gateway {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The display name of the gateway.</p>
    pub fn gateway_display_name(&self) -> ::std::option::Option<&str> {
        self.gateway_display_name.as_deref()
    }
    /// <p>The type of the gateway.</p>
    pub fn gateway_type(&self) -> ::std::option::Option<&crate::types::GatewayType> {
        self.gateway_type.as_ref()
    }
    /// <p>The hypervisor ID of the gateway.</p>
    pub fn hypervisor_id(&self) -> ::std::option::Option<&str> {
        self.hypervisor_id.as_deref()
    }
    /// <p>The last time Backup gateway communicated with the gateway, in Unix format and UTC time.</p>
    pub fn last_seen_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_seen_time.as_ref()
    }
}
impl Gateway {
    /// Creates a new builder-style object to manufacture [`Gateway`](crate::types::Gateway).
    pub fn builder() -> crate::types::builders::GatewayBuilder {
        crate::types::builders::GatewayBuilder::default()
    }
}

/// A builder for [`Gateway`](crate::types::Gateway).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GatewayBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) gateway_type: ::std::option::Option<crate::types::GatewayType>,
    pub(crate) hypervisor_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_seen_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl GatewayBuilder {
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
    /// <p>The display name of the gateway.</p>
    pub fn gateway_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the gateway.</p>
    pub fn set_gateway_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_display_name = input;
        self
    }
    /// <p>The display name of the gateway.</p>
    pub fn get_gateway_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_display_name
    }
    /// <p>The type of the gateway.</p>
    pub fn gateway_type(mut self, input: crate::types::GatewayType) -> Self {
        self.gateway_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the gateway.</p>
    pub fn set_gateway_type(mut self, input: ::std::option::Option<crate::types::GatewayType>) -> Self {
        self.gateway_type = input;
        self
    }
    /// <p>The type of the gateway.</p>
    pub fn get_gateway_type(&self) -> &::std::option::Option<crate::types::GatewayType> {
        &self.gateway_type
    }
    /// <p>The hypervisor ID of the gateway.</p>
    pub fn hypervisor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hypervisor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hypervisor ID of the gateway.</p>
    pub fn set_hypervisor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hypervisor_id = input;
        self
    }
    /// <p>The hypervisor ID of the gateway.</p>
    pub fn get_hypervisor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hypervisor_id
    }
    /// <p>The last time Backup gateway communicated with the gateway, in Unix format and UTC time.</p>
    pub fn last_seen_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_seen_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time Backup gateway communicated with the gateway, in Unix format and UTC time.</p>
    pub fn set_last_seen_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_seen_time = input;
        self
    }
    /// <p>The last time Backup gateway communicated with the gateway, in Unix format and UTC time.</p>
    pub fn get_last_seen_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_seen_time
    }
    /// Consumes the builder and constructs a [`Gateway`](crate::types::Gateway).
    pub fn build(self) -> crate::types::Gateway {
        crate::types::Gateway {
            gateway_arn: self.gateway_arn,
            gateway_display_name: self.gateway_display_name,
            gateway_type: self.gateway_type,
            hypervisor_id: self.hypervisor_id,
            last_seen_time: self.last_seen_time,
        }
    }
}
