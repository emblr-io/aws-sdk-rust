// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteResourceEndpointAssociationOutput {
    /// <p>The ID of the association.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource configuration.</p>
    pub resource_configuration_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the resource configuration associated with the VPC endpoint of type resource.</p>
    pub resource_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource VPC endpoint that is associated with the resource configuration.</p>
    pub vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourceEndpointAssociationOutput {
    /// <p>The ID of the association.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn resource_configuration_id(&self) -> ::std::option::Option<&str> {
        self.resource_configuration_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration associated with the VPC endpoint of type resource.</p>
    pub fn resource_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.resource_configuration_arn.as_deref()
    }
    /// <p>The ID of the resource VPC endpoint that is associated with the resource configuration.</p>
    pub fn vpc_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteResourceEndpointAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteResourceEndpointAssociationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteResourceEndpointAssociationOutput`](crate::operation::delete_resource_endpoint_association::DeleteResourceEndpointAssociationOutput).
    pub fn builder() -> crate::operation::delete_resource_endpoint_association::builders::DeleteResourceEndpointAssociationOutputBuilder {
        crate::operation::delete_resource_endpoint_association::builders::DeleteResourceEndpointAssociationOutputBuilder::default()
    }
}

/// A builder for [`DeleteResourceEndpointAssociationOutput`](crate::operation::delete_resource_endpoint_association::DeleteResourceEndpointAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteResourceEndpointAssociationOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_configuration_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_endpoint_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteResourceEndpointAssociationOutputBuilder {
    /// <p>The ID of the association.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the association.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the association.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn resource_configuration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_configuration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn set_resource_configuration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_configuration_id = input;
        self
    }
    /// <p>The ID of the resource configuration.</p>
    pub fn get_resource_configuration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_configuration_id
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration associated with the VPC endpoint of type resource.</p>
    pub fn resource_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration associated with the VPC endpoint of type resource.</p>
    pub fn set_resource_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource configuration associated with the VPC endpoint of type resource.</p>
    pub fn get_resource_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_configuration_arn
    }
    /// <p>The ID of the resource VPC endpoint that is associated with the resource configuration.</p>
    pub fn vpc_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource VPC endpoint that is associated with the resource configuration.</p>
    pub fn set_vpc_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_id = input;
        self
    }
    /// <p>The ID of the resource VPC endpoint that is associated with the resource configuration.</p>
    pub fn get_vpc_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteResourceEndpointAssociationOutput`](crate::operation::delete_resource_endpoint_association::DeleteResourceEndpointAssociationOutput).
    pub fn build(self) -> crate::operation::delete_resource_endpoint_association::DeleteResourceEndpointAssociationOutput {
        crate::operation::delete_resource_endpoint_association::DeleteResourceEndpointAssociationOutput {
            id: self.id,
            arn: self.arn,
            resource_configuration_id: self.resource_configuration_id,
            resource_configuration_arn: self.resource_configuration_arn,
            vpc_endpoint_id: self.vpc_endpoint_id,
            _request_id: self._request_id,
        }
    }
}
