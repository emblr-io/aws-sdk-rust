// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a target network that is associated with a Client VPN endpoint. A target network is a subnet in a VPC.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociatedTargetNetwork {
    /// <p>The ID of the subnet.</p>
    pub network_id: ::std::option::Option<::std::string::String>,
    /// <p>The target network type.</p>
    pub network_type: ::std::option::Option<crate::types::AssociatedNetworkType>,
}
impl AssociatedTargetNetwork {
    /// <p>The ID of the subnet.</p>
    pub fn network_id(&self) -> ::std::option::Option<&str> {
        self.network_id.as_deref()
    }
    /// <p>The target network type.</p>
    pub fn network_type(&self) -> ::std::option::Option<&crate::types::AssociatedNetworkType> {
        self.network_type.as_ref()
    }
}
impl AssociatedTargetNetwork {
    /// Creates a new builder-style object to manufacture [`AssociatedTargetNetwork`](crate::types::AssociatedTargetNetwork).
    pub fn builder() -> crate::types::builders::AssociatedTargetNetworkBuilder {
        crate::types::builders::AssociatedTargetNetworkBuilder::default()
    }
}

/// A builder for [`AssociatedTargetNetwork`](crate::types::AssociatedTargetNetwork).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociatedTargetNetworkBuilder {
    pub(crate) network_id: ::std::option::Option<::std::string::String>,
    pub(crate) network_type: ::std::option::Option<crate::types::AssociatedNetworkType>,
}
impl AssociatedTargetNetworkBuilder {
    /// <p>The ID of the subnet.</p>
    pub fn network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet.</p>
    pub fn set_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_id = input;
        self
    }
    /// <p>The ID of the subnet.</p>
    pub fn get_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_id
    }
    /// <p>The target network type.</p>
    pub fn network_type(mut self, input: crate::types::AssociatedNetworkType) -> Self {
        self.network_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target network type.</p>
    pub fn set_network_type(mut self, input: ::std::option::Option<crate::types::AssociatedNetworkType>) -> Self {
        self.network_type = input;
        self
    }
    /// <p>The target network type.</p>
    pub fn get_network_type(&self) -> &::std::option::Option<crate::types::AssociatedNetworkType> {
        &self.network_type
    }
    /// Consumes the builder and constructs a [`AssociatedTargetNetwork`](crate::types::AssociatedTargetNetwork).
    pub fn build(self) -> crate::types::AssociatedTargetNetwork {
        crate::types::AssociatedTargetNetwork {
            network_id: self.network_id,
            network_type: self.network_type,
        }
    }
}
