// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A remote resource is the other endpoint in a network flow. That is, one endpoint is the local resource and the other is the remote resource. Remote resources can be a a subnet, a VPC, an Availability Zone, or an Amazon Web Services service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MonitorRemoteResource {
    /// <p>The type of the remote resource. Valid values are <code>AWS::EC2::VPC</code> <code>AWS::AvailabilityZone</code>, <code>AWS::EC2::Subnet</code>, or <code>AWS::AWSService</code>.</p>
    pub r#type: crate::types::MonitorRemoteResourceType,
    /// <p>The identifier of the remote resource, such as an ARN.</p>
    pub identifier: ::std::string::String,
}
impl MonitorRemoteResource {
    /// <p>The type of the remote resource. Valid values are <code>AWS::EC2::VPC</code> <code>AWS::AvailabilityZone</code>, <code>AWS::EC2::Subnet</code>, or <code>AWS::AWSService</code>.</p>
    pub fn r#type(&self) -> &crate::types::MonitorRemoteResourceType {
        &self.r#type
    }
    /// <p>The identifier of the remote resource, such as an ARN.</p>
    pub fn identifier(&self) -> &str {
        use std::ops::Deref;
        self.identifier.deref()
    }
}
impl MonitorRemoteResource {
    /// Creates a new builder-style object to manufacture [`MonitorRemoteResource`](crate::types::MonitorRemoteResource).
    pub fn builder() -> crate::types::builders::MonitorRemoteResourceBuilder {
        crate::types::builders::MonitorRemoteResourceBuilder::default()
    }
}

/// A builder for [`MonitorRemoteResource`](crate::types::MonitorRemoteResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MonitorRemoteResourceBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::MonitorRemoteResourceType>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl MonitorRemoteResourceBuilder {
    /// <p>The type of the remote resource. Valid values are <code>AWS::EC2::VPC</code> <code>AWS::AvailabilityZone</code>, <code>AWS::EC2::Subnet</code>, or <code>AWS::AWSService</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::MonitorRemoteResourceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the remote resource. Valid values are <code>AWS::EC2::VPC</code> <code>AWS::AvailabilityZone</code>, <code>AWS::EC2::Subnet</code>, or <code>AWS::AWSService</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::MonitorRemoteResourceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the remote resource. Valid values are <code>AWS::EC2::VPC</code> <code>AWS::AvailabilityZone</code>, <code>AWS::EC2::Subnet</code>, or <code>AWS::AWSService</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::MonitorRemoteResourceType> {
        &self.r#type
    }
    /// <p>The identifier of the remote resource, such as an ARN.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the remote resource, such as an ARN.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the remote resource, such as an ARN.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`MonitorRemoteResource`](crate::types::MonitorRemoteResource).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::MonitorRemoteResourceBuilder::type)
    /// - [`identifier`](crate::types::builders::MonitorRemoteResourceBuilder::identifier)
    pub fn build(self) -> ::std::result::Result<crate::types::MonitorRemoteResource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MonitorRemoteResource {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building MonitorRemoteResource",
                )
            })?,
            identifier: self.identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identifier",
                    "identifier was not specified but it is required when building MonitorRemoteResource",
                )
            })?,
        })
    }
}
