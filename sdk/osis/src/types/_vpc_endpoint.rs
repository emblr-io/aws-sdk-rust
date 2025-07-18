// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An OpenSearch Ingestion-managed VPC endpoint that will access one or more pipelines.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpcEndpoint {
    /// <p>The unique identifier of the endpoint.</p>
    pub vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for your VPC. Amazon Web Services PrivateLink generates this value when you create a VPC.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the VPC, including associated subnets and security groups.</p>
    pub vpc_options: ::std::option::Option<crate::types::VpcOptions>,
}
impl VpcEndpoint {
    /// <p>The unique identifier of the endpoint.</p>
    pub fn vpc_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_id.as_deref()
    }
    /// <p>The ID for your VPC. Amazon Web Services PrivateLink generates this value when you create a VPC.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Information about the VPC, including associated subnets and security groups.</p>
    pub fn vpc_options(&self) -> ::std::option::Option<&crate::types::VpcOptions> {
        self.vpc_options.as_ref()
    }
}
impl VpcEndpoint {
    /// Creates a new builder-style object to manufacture [`VpcEndpoint`](crate::types::VpcEndpoint).
    pub fn builder() -> crate::types::builders::VpcEndpointBuilder {
        crate::types::builders::VpcEndpointBuilder::default()
    }
}

/// A builder for [`VpcEndpoint`](crate::types::VpcEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpcEndpointBuilder {
    pub(crate) vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_options: ::std::option::Option<crate::types::VpcOptions>,
}
impl VpcEndpointBuilder {
    /// <p>The unique identifier of the endpoint.</p>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the endpoint.</p>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_id = input;
        self
    }
    /// <p>The unique identifier of the endpoint.</p>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_id
    }
    /// <p>The ID for your VPC. Amazon Web Services PrivateLink generates this value when you create a VPC.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for your VPC. Amazon Web Services PrivateLink generates this value when you create a VPC.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The ID for your VPC. Amazon Web Services PrivateLink generates this value when you create a VPC.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>Information about the VPC, including associated subnets and security groups.</p>
    pub fn vpc_options(mut self, input: crate::types::VpcOptions) -> Self {
        self.vpc_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the VPC, including associated subnets and security groups.</p>
    pub fn set_vpc_options(mut self, input: ::std::option::Option<crate::types::VpcOptions>) -> Self {
        self.vpc_options = input;
        self
    }
    /// <p>Information about the VPC, including associated subnets and security groups.</p>
    pub fn get_vpc_options(&self) -> &::std::option::Option<crate::types::VpcOptions> {
        &self.vpc_options
    }
    /// Consumes the builder and constructs a [`VpcEndpoint`](crate::types::VpcEndpoint).
    pub fn build(self) -> crate::types::VpcEndpoint {
        crate::types::VpcEndpoint {
            vpc_endpoint_id: self.vpc_endpoint_id,
            vpc_id: self.vpc_id,
            vpc_options: self.vpc_options,
        }
    }
}
