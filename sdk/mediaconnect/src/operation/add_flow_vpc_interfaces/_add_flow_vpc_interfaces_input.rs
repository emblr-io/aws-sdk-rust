// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddFlowVpcInterfacesInput {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub flow_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of VPC interfaces that you want to add to the flow.</p>
    pub vpc_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>,
}
impl AddFlowVpcInterfacesInput {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn flow_arn(&self) -> ::std::option::Option<&str> {
        self.flow_arn.as_deref()
    }
    /// <p>A list of VPC interfaces that you want to add to the flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_interfaces.is_none()`.
    pub fn vpc_interfaces(&self) -> &[crate::types::VpcInterfaceRequest] {
        self.vpc_interfaces.as_deref().unwrap_or_default()
    }
}
impl AddFlowVpcInterfacesInput {
    /// Creates a new builder-style object to manufacture [`AddFlowVpcInterfacesInput`](crate::operation::add_flow_vpc_interfaces::AddFlowVpcInterfacesInput).
    pub fn builder() -> crate::operation::add_flow_vpc_interfaces::builders::AddFlowVpcInterfacesInputBuilder {
        crate::operation::add_flow_vpc_interfaces::builders::AddFlowVpcInterfacesInputBuilder::default()
    }
}

/// A builder for [`AddFlowVpcInterfacesInput`](crate::operation::add_flow_vpc_interfaces::AddFlowVpcInterfacesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddFlowVpcInterfacesInputBuilder {
    pub(crate) flow_arn: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>,
}
impl AddFlowVpcInterfacesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    /// This field is required.
    pub fn flow_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn set_flow_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the flow that you want to update.</p>
    pub fn get_flow_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_arn
    }
    /// Appends an item to `vpc_interfaces`.
    ///
    /// To override the contents of this collection use [`set_vpc_interfaces`](Self::set_vpc_interfaces).
    ///
    /// <p>A list of VPC interfaces that you want to add to the flow.</p>
    pub fn vpc_interfaces(mut self, input: crate::types::VpcInterfaceRequest) -> Self {
        let mut v = self.vpc_interfaces.unwrap_or_default();
        v.push(input);
        self.vpc_interfaces = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of VPC interfaces that you want to add to the flow.</p>
    pub fn set_vpc_interfaces(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>>) -> Self {
        self.vpc_interfaces = input;
        self
    }
    /// <p>A list of VPC interfaces that you want to add to the flow.</p>
    pub fn get_vpc_interfaces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcInterfaceRequest>> {
        &self.vpc_interfaces
    }
    /// Consumes the builder and constructs a [`AddFlowVpcInterfacesInput`](crate::operation::add_flow_vpc_interfaces::AddFlowVpcInterfacesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::add_flow_vpc_interfaces::AddFlowVpcInterfacesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::add_flow_vpc_interfaces::AddFlowVpcInterfacesInput {
            flow_arn: self.flow_arn,
            vpc_interfaces: self.vpc_interfaces,
        })
    }
}
