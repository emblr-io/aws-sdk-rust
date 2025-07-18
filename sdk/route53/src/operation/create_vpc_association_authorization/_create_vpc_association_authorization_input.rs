// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about the request to authorize associating a VPC with your private hosted zone. Authorization is only required when a private hosted zone and a VPC were created by using different accounts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVpcAssociationAuthorizationInput {
    /// <p>The ID of the private hosted zone that you want to authorize associating a VPC with.</p>
    pub hosted_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>A complex type that contains the VPC ID and region for the VPC that you want to authorize associating with your hosted zone.</p>
    pub vpc: ::std::option::Option<crate::types::Vpc>,
}
impl CreateVpcAssociationAuthorizationInput {
    /// <p>The ID of the private hosted zone that you want to authorize associating a VPC with.</p>
    pub fn hosted_zone_id(&self) -> ::std::option::Option<&str> {
        self.hosted_zone_id.as_deref()
    }
    /// <p>A complex type that contains the VPC ID and region for the VPC that you want to authorize associating with your hosted zone.</p>
    pub fn vpc(&self) -> ::std::option::Option<&crate::types::Vpc> {
        self.vpc.as_ref()
    }
}
impl CreateVpcAssociationAuthorizationInput {
    /// Creates a new builder-style object to manufacture [`CreateVpcAssociationAuthorizationInput`](crate::operation::create_vpc_association_authorization::CreateVpcAssociationAuthorizationInput).
    pub fn builder() -> crate::operation::create_vpc_association_authorization::builders::CreateVpcAssociationAuthorizationInputBuilder {
        crate::operation::create_vpc_association_authorization::builders::CreateVpcAssociationAuthorizationInputBuilder::default()
    }
}

/// A builder for [`CreateVpcAssociationAuthorizationInput`](crate::operation::create_vpc_association_authorization::CreateVpcAssociationAuthorizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVpcAssociationAuthorizationInputBuilder {
    pub(crate) hosted_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc: ::std::option::Option<crate::types::Vpc>,
}
impl CreateVpcAssociationAuthorizationInputBuilder {
    /// <p>The ID of the private hosted zone that you want to authorize associating a VPC with.</p>
    /// This field is required.
    pub fn hosted_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hosted_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the private hosted zone that you want to authorize associating a VPC with.</p>
    pub fn set_hosted_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hosted_zone_id = input;
        self
    }
    /// <p>The ID of the private hosted zone that you want to authorize associating a VPC with.</p>
    pub fn get_hosted_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hosted_zone_id
    }
    /// <p>A complex type that contains the VPC ID and region for the VPC that you want to authorize associating with your hosted zone.</p>
    /// This field is required.
    pub fn vpc(mut self, input: crate::types::Vpc) -> Self {
        self.vpc = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains the VPC ID and region for the VPC that you want to authorize associating with your hosted zone.</p>
    pub fn set_vpc(mut self, input: ::std::option::Option<crate::types::Vpc>) -> Self {
        self.vpc = input;
        self
    }
    /// <p>A complex type that contains the VPC ID and region for the VPC that you want to authorize associating with your hosted zone.</p>
    pub fn get_vpc(&self) -> &::std::option::Option<crate::types::Vpc> {
        &self.vpc
    }
    /// Consumes the builder and constructs a [`CreateVpcAssociationAuthorizationInput`](crate::operation::create_vpc_association_authorization::CreateVpcAssociationAuthorizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_vpc_association_authorization::CreateVpcAssociationAuthorizationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_vpc_association_authorization::CreateVpcAssociationAuthorizationInput {
                hosted_zone_id: self.hosted_zone_id,
                vpc: self.vpc,
            },
        )
    }
}
