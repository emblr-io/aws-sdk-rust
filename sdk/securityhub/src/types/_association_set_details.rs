// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The associations between a route table and one or more subnets or a gateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociationSetDetails {
    /// <p>The state of the association between a route table and a subnet or gateway.</p>
    pub association_state: ::std::option::Option<crate::types::AssociationStateDetails>,
    /// <p>The ID of the internet gateway or virtual private gateway.</p>
    pub gateway_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether this is the main route table.</p>
    pub main: ::std::option::Option<bool>,
    /// <p>The ID of the association.</p>
    pub route_table_association_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the route table.</p>
    pub route_table_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subnet. A subnet ID is not returned for an implicit association.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
}
impl AssociationSetDetails {
    /// <p>The state of the association between a route table and a subnet or gateway.</p>
    pub fn association_state(&self) -> ::std::option::Option<&crate::types::AssociationStateDetails> {
        self.association_state.as_ref()
    }
    /// <p>The ID of the internet gateway or virtual private gateway.</p>
    pub fn gateway_id(&self) -> ::std::option::Option<&str> {
        self.gateway_id.as_deref()
    }
    /// <p>Indicates whether this is the main route table.</p>
    pub fn main(&self) -> ::std::option::Option<bool> {
        self.main
    }
    /// <p>The ID of the association.</p>
    pub fn route_table_association_id(&self) -> ::std::option::Option<&str> {
        self.route_table_association_id.as_deref()
    }
    /// <p>The ID of the route table.</p>
    pub fn route_table_id(&self) -> ::std::option::Option<&str> {
        self.route_table_id.as_deref()
    }
    /// <p>The ID of the subnet. A subnet ID is not returned for an implicit association.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
}
impl AssociationSetDetails {
    /// Creates a new builder-style object to manufacture [`AssociationSetDetails`](crate::types::AssociationSetDetails).
    pub fn builder() -> crate::types::builders::AssociationSetDetailsBuilder {
        crate::types::builders::AssociationSetDetailsBuilder::default()
    }
}

/// A builder for [`AssociationSetDetails`](crate::types::AssociationSetDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociationSetDetailsBuilder {
    pub(crate) association_state: ::std::option::Option<crate::types::AssociationStateDetails>,
    pub(crate) gateway_id: ::std::option::Option<::std::string::String>,
    pub(crate) main: ::std::option::Option<bool>,
    pub(crate) route_table_association_id: ::std::option::Option<::std::string::String>,
    pub(crate) route_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
}
impl AssociationSetDetailsBuilder {
    /// <p>The state of the association between a route table and a subnet or gateway.</p>
    pub fn association_state(mut self, input: crate::types::AssociationStateDetails) -> Self {
        self.association_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the association between a route table and a subnet or gateway.</p>
    pub fn set_association_state(mut self, input: ::std::option::Option<crate::types::AssociationStateDetails>) -> Self {
        self.association_state = input;
        self
    }
    /// <p>The state of the association between a route table and a subnet or gateway.</p>
    pub fn get_association_state(&self) -> &::std::option::Option<crate::types::AssociationStateDetails> {
        &self.association_state
    }
    /// <p>The ID of the internet gateway or virtual private gateway.</p>
    pub fn gateway_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the internet gateway or virtual private gateway.</p>
    pub fn set_gateway_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_id = input;
        self
    }
    /// <p>The ID of the internet gateway or virtual private gateway.</p>
    pub fn get_gateway_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_id
    }
    /// <p>Indicates whether this is the main route table.</p>
    pub fn main(mut self, input: bool) -> Self {
        self.main = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether this is the main route table.</p>
    pub fn set_main(mut self, input: ::std::option::Option<bool>) -> Self {
        self.main = input;
        self
    }
    /// <p>Indicates whether this is the main route table.</p>
    pub fn get_main(&self) -> &::std::option::Option<bool> {
        &self.main
    }
    /// <p>The ID of the association.</p>
    pub fn route_table_association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_table_association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the association.</p>
    pub fn set_route_table_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_table_association_id = input;
        self
    }
    /// <p>The ID of the association.</p>
    pub fn get_route_table_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_table_association_id
    }
    /// <p>The ID of the route table.</p>
    pub fn route_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the route table.</p>
    pub fn set_route_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_table_id = input;
        self
    }
    /// <p>The ID of the route table.</p>
    pub fn get_route_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_table_id
    }
    /// <p>The ID of the subnet. A subnet ID is not returned for an implicit association.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet. A subnet ID is not returned for an implicit association.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The ID of the subnet. A subnet ID is not returned for an implicit association.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// Consumes the builder and constructs a [`AssociationSetDetails`](crate::types::AssociationSetDetails).
    pub fn build(self) -> crate::types::AssociationSetDetails {
        crate::types::AssociationSetDetails {
            association_state: self.association_state,
            gateway_id: self.gateway_id,
            main: self.main,
            route_table_association_id: self.route_table_association_id,
            route_table_id: self.route_table_id,
            subnet_id: self.subnet_id,
        }
    }
}
