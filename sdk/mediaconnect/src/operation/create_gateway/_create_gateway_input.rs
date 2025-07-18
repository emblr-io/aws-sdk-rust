// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGatewayInput {
    /// <p>The range of IP addresses that are allowed to contribute content or initiate output requests for flows communicating with this gateway. These IP addresses should be in the form of a Classless Inter-Domain Routing (CIDR) block; for example, 10.0.0.0/16.</p>
    pub egress_cidr_blocks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the gateway. This name can not be modified after the gateway is created.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The list of networks that you want to add to the gateway.</p>
    pub networks: ::std::option::Option<::std::vec::Vec<crate::types::GatewayNetwork>>,
}
impl CreateGatewayInput {
    /// <p>The range of IP addresses that are allowed to contribute content or initiate output requests for flows communicating with this gateway. These IP addresses should be in the form of a Classless Inter-Domain Routing (CIDR) block; for example, 10.0.0.0/16.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.egress_cidr_blocks.is_none()`.
    pub fn egress_cidr_blocks(&self) -> &[::std::string::String] {
        self.egress_cidr_blocks.as_deref().unwrap_or_default()
    }
    /// <p>The name of the gateway. This name can not be modified after the gateway is created.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The list of networks that you want to add to the gateway.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.networks.is_none()`.
    pub fn networks(&self) -> &[crate::types::GatewayNetwork] {
        self.networks.as_deref().unwrap_or_default()
    }
}
impl CreateGatewayInput {
    /// Creates a new builder-style object to manufacture [`CreateGatewayInput`](crate::operation::create_gateway::CreateGatewayInput).
    pub fn builder() -> crate::operation::create_gateway::builders::CreateGatewayInputBuilder {
        crate::operation::create_gateway::builders::CreateGatewayInputBuilder::default()
    }
}

/// A builder for [`CreateGatewayInput`](crate::operation::create_gateway::CreateGatewayInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGatewayInputBuilder {
    pub(crate) egress_cidr_blocks: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) networks: ::std::option::Option<::std::vec::Vec<crate::types::GatewayNetwork>>,
}
impl CreateGatewayInputBuilder {
    /// Appends an item to `egress_cidr_blocks`.
    ///
    /// To override the contents of this collection use [`set_egress_cidr_blocks`](Self::set_egress_cidr_blocks).
    ///
    /// <p>The range of IP addresses that are allowed to contribute content or initiate output requests for flows communicating with this gateway. These IP addresses should be in the form of a Classless Inter-Domain Routing (CIDR) block; for example, 10.0.0.0/16.</p>
    pub fn egress_cidr_blocks(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.egress_cidr_blocks.unwrap_or_default();
        v.push(input.into());
        self.egress_cidr_blocks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The range of IP addresses that are allowed to contribute content or initiate output requests for flows communicating with this gateway. These IP addresses should be in the form of a Classless Inter-Domain Routing (CIDR) block; for example, 10.0.0.0/16.</p>
    pub fn set_egress_cidr_blocks(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.egress_cidr_blocks = input;
        self
    }
    /// <p>The range of IP addresses that are allowed to contribute content or initiate output requests for flows communicating with this gateway. These IP addresses should be in the form of a Classless Inter-Domain Routing (CIDR) block; for example, 10.0.0.0/16.</p>
    pub fn get_egress_cidr_blocks(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.egress_cidr_blocks
    }
    /// <p>The name of the gateway. This name can not be modified after the gateway is created.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the gateway. This name can not be modified after the gateway is created.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the gateway. This name can not be modified after the gateway is created.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `networks`.
    ///
    /// To override the contents of this collection use [`set_networks`](Self::set_networks).
    ///
    /// <p>The list of networks that you want to add to the gateway.</p>
    pub fn networks(mut self, input: crate::types::GatewayNetwork) -> Self {
        let mut v = self.networks.unwrap_or_default();
        v.push(input);
        self.networks = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of networks that you want to add to the gateway.</p>
    pub fn set_networks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GatewayNetwork>>) -> Self {
        self.networks = input;
        self
    }
    /// <p>The list of networks that you want to add to the gateway.</p>
    pub fn get_networks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GatewayNetwork>> {
        &self.networks
    }
    /// Consumes the builder and constructs a [`CreateGatewayInput`](crate::operation::create_gateway::CreateGatewayInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_gateway::CreateGatewayInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_gateway::CreateGatewayInput {
            egress_cidr_blocks: self.egress_cidr_blocks,
            name: self.name,
            networks: self.networks,
        })
    }
}
