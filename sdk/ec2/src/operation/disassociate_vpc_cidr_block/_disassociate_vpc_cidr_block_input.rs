// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateVpcCidrBlockInput {
    /// <p>The association ID for the CIDR block.</p>
    pub association_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateVpcCidrBlockInput {
    /// <p>The association ID for the CIDR block.</p>
    pub fn association_id(&self) -> ::std::option::Option<&str> {
        self.association_id.as_deref()
    }
}
impl DisassociateVpcCidrBlockInput {
    /// Creates a new builder-style object to manufacture [`DisassociateVpcCidrBlockInput`](crate::operation::disassociate_vpc_cidr_block::DisassociateVpcCidrBlockInput).
    pub fn builder() -> crate::operation::disassociate_vpc_cidr_block::builders::DisassociateVpcCidrBlockInputBuilder {
        crate::operation::disassociate_vpc_cidr_block::builders::DisassociateVpcCidrBlockInputBuilder::default()
    }
}

/// A builder for [`DisassociateVpcCidrBlockInput`](crate::operation::disassociate_vpc_cidr_block::DisassociateVpcCidrBlockInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateVpcCidrBlockInputBuilder {
    pub(crate) association_id: ::std::option::Option<::std::string::String>,
}
impl DisassociateVpcCidrBlockInputBuilder {
    /// <p>The association ID for the CIDR block.</p>
    /// This field is required.
    pub fn association_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.association_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The association ID for the CIDR block.</p>
    pub fn set_association_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.association_id = input;
        self
    }
    /// <p>The association ID for the CIDR block.</p>
    pub fn get_association_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.association_id
    }
    /// Consumes the builder and constructs a [`DisassociateVpcCidrBlockInput`](crate::operation::disassociate_vpc_cidr_block::DisassociateVpcCidrBlockInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_vpc_cidr_block::DisassociateVpcCidrBlockInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_vpc_cidr_block::DisassociateVpcCidrBlockInput {
            association_id: self.association_id,
        })
    }
}
