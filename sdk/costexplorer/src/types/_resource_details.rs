// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details for the resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceDetails {
    /// <p>Details for the Amazon EC2 resource.</p>
    pub ec2_resource_details: ::std::option::Option<crate::types::Ec2ResourceDetails>,
}
impl ResourceDetails {
    /// <p>Details for the Amazon EC2 resource.</p>
    pub fn ec2_resource_details(&self) -> ::std::option::Option<&crate::types::Ec2ResourceDetails> {
        self.ec2_resource_details.as_ref()
    }
}
impl ResourceDetails {
    /// Creates a new builder-style object to manufacture [`ResourceDetails`](crate::types::ResourceDetails).
    pub fn builder() -> crate::types::builders::ResourceDetailsBuilder {
        crate::types::builders::ResourceDetailsBuilder::default()
    }
}

/// A builder for [`ResourceDetails`](crate::types::ResourceDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceDetailsBuilder {
    pub(crate) ec2_resource_details: ::std::option::Option<crate::types::Ec2ResourceDetails>,
}
impl ResourceDetailsBuilder {
    /// <p>Details for the Amazon EC2 resource.</p>
    pub fn ec2_resource_details(mut self, input: crate::types::Ec2ResourceDetails) -> Self {
        self.ec2_resource_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the Amazon EC2 resource.</p>
    pub fn set_ec2_resource_details(mut self, input: ::std::option::Option<crate::types::Ec2ResourceDetails>) -> Self {
        self.ec2_resource_details = input;
        self
    }
    /// <p>Details for the Amazon EC2 resource.</p>
    pub fn get_ec2_resource_details(&self) -> &::std::option::Option<crate::types::Ec2ResourceDetails> {
        &self.ec2_resource_details
    }
    /// Consumes the builder and constructs a [`ResourceDetails`](crate::types::ResourceDetails).
    pub fn build(self) -> crate::types::ResourceDetails {
        crate::types::ResourceDetails {
            ec2_resource_details: self.ec2_resource_details,
        }
    }
}
