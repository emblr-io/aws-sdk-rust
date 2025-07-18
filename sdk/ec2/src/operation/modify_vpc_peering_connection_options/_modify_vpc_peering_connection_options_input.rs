// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyVpcPeeringConnectionOptionsInput {
    /// <p>The VPC peering connection options for the accepter VPC.</p>
    pub accepter_peering_connection_options: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The VPC peering connection options for the requester VPC.</p>
    pub requester_peering_connection_options: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>,
    /// <p>The ID of the VPC peering connection.</p>
    pub vpc_peering_connection_id: ::std::option::Option<::std::string::String>,
}
impl ModifyVpcPeeringConnectionOptionsInput {
    /// <p>The VPC peering connection options for the accepter VPC.</p>
    pub fn accepter_peering_connection_options(&self) -> ::std::option::Option<&crate::types::PeeringConnectionOptionsRequest> {
        self.accepter_peering_connection_options.as_ref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The VPC peering connection options for the requester VPC.</p>
    pub fn requester_peering_connection_options(&self) -> ::std::option::Option<&crate::types::PeeringConnectionOptionsRequest> {
        self.requester_peering_connection_options.as_ref()
    }
    /// <p>The ID of the VPC peering connection.</p>
    pub fn vpc_peering_connection_id(&self) -> ::std::option::Option<&str> {
        self.vpc_peering_connection_id.as_deref()
    }
}
impl ModifyVpcPeeringConnectionOptionsInput {
    /// Creates a new builder-style object to manufacture [`ModifyVpcPeeringConnectionOptionsInput`](crate::operation::modify_vpc_peering_connection_options::ModifyVpcPeeringConnectionOptionsInput).
    pub fn builder() -> crate::operation::modify_vpc_peering_connection_options::builders::ModifyVpcPeeringConnectionOptionsInputBuilder {
        crate::operation::modify_vpc_peering_connection_options::builders::ModifyVpcPeeringConnectionOptionsInputBuilder::default()
    }
}

/// A builder for [`ModifyVpcPeeringConnectionOptionsInput`](crate::operation::modify_vpc_peering_connection_options::ModifyVpcPeeringConnectionOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyVpcPeeringConnectionOptionsInputBuilder {
    pub(crate) accepter_peering_connection_options: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) requester_peering_connection_options: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>,
    pub(crate) vpc_peering_connection_id: ::std::option::Option<::std::string::String>,
}
impl ModifyVpcPeeringConnectionOptionsInputBuilder {
    /// <p>The VPC peering connection options for the accepter VPC.</p>
    pub fn accepter_peering_connection_options(mut self, input: crate::types::PeeringConnectionOptionsRequest) -> Self {
        self.accepter_peering_connection_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VPC peering connection options for the accepter VPC.</p>
    pub fn set_accepter_peering_connection_options(mut self, input: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>) -> Self {
        self.accepter_peering_connection_options = input;
        self
    }
    /// <p>The VPC peering connection options for the accepter VPC.</p>
    pub fn get_accepter_peering_connection_options(&self) -> &::std::option::Option<crate::types::PeeringConnectionOptionsRequest> {
        &self.accepter_peering_connection_options
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
    /// <p>The VPC peering connection options for the requester VPC.</p>
    pub fn requester_peering_connection_options(mut self, input: crate::types::PeeringConnectionOptionsRequest) -> Self {
        self.requester_peering_connection_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VPC peering connection options for the requester VPC.</p>
    pub fn set_requester_peering_connection_options(mut self, input: ::std::option::Option<crate::types::PeeringConnectionOptionsRequest>) -> Self {
        self.requester_peering_connection_options = input;
        self
    }
    /// <p>The VPC peering connection options for the requester VPC.</p>
    pub fn get_requester_peering_connection_options(&self) -> &::std::option::Option<crate::types::PeeringConnectionOptionsRequest> {
        &self.requester_peering_connection_options
    }
    /// <p>The ID of the VPC peering connection.</p>
    /// This field is required.
    pub fn vpc_peering_connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_peering_connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the VPC peering connection.</p>
    pub fn set_vpc_peering_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_peering_connection_id = input;
        self
    }
    /// <p>The ID of the VPC peering connection.</p>
    pub fn get_vpc_peering_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_peering_connection_id
    }
    /// Consumes the builder and constructs a [`ModifyVpcPeeringConnectionOptionsInput`](crate::operation::modify_vpc_peering_connection_options::ModifyVpcPeeringConnectionOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_vpc_peering_connection_options::ModifyVpcPeeringConnectionOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_vpc_peering_connection_options::ModifyVpcPeeringConnectionOptionsInput {
                accepter_peering_connection_options: self.accepter_peering_connection_options,
                dry_run: self.dry_run,
                requester_peering_connection_options: self.requester_peering_connection_options,
                vpc_peering_connection_id: self.vpc_peering_connection_id,
            },
        )
    }
}
