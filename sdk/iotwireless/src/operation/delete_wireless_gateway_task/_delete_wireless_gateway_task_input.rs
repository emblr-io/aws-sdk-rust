// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteWirelessGatewayTaskInput {
    /// <p>The ID of the resource to delete.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl DeleteWirelessGatewayTaskInput {
    /// <p>The ID of the resource to delete.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DeleteWirelessGatewayTaskInput {
    /// Creates a new builder-style object to manufacture [`DeleteWirelessGatewayTaskInput`](crate::operation::delete_wireless_gateway_task::DeleteWirelessGatewayTaskInput).
    pub fn builder() -> crate::operation::delete_wireless_gateway_task::builders::DeleteWirelessGatewayTaskInputBuilder {
        crate::operation::delete_wireless_gateway_task::builders::DeleteWirelessGatewayTaskInputBuilder::default()
    }
}

/// A builder for [`DeleteWirelessGatewayTaskInput`](crate::operation::delete_wireless_gateway_task::DeleteWirelessGatewayTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteWirelessGatewayTaskInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DeleteWirelessGatewayTaskInputBuilder {
    /// <p>The ID of the resource to delete.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource to delete.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the resource to delete.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DeleteWirelessGatewayTaskInput`](crate::operation::delete_wireless_gateway_task::DeleteWirelessGatewayTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_wireless_gateway_task::DeleteWirelessGatewayTaskInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_wireless_gateway_task::DeleteWirelessGatewayTaskInput { id: self.id })
    }
}
