// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCustomRoutingAcceleratorInput {
    /// <p>The Amazon Resource Name (ARN) of the custom routing accelerator to delete.</p>
    pub accelerator_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteCustomRoutingAcceleratorInput {
    /// <p>The Amazon Resource Name (ARN) of the custom routing accelerator to delete.</p>
    pub fn accelerator_arn(&self) -> ::std::option::Option<&str> {
        self.accelerator_arn.as_deref()
    }
}
impl DeleteCustomRoutingAcceleratorInput {
    /// Creates a new builder-style object to manufacture [`DeleteCustomRoutingAcceleratorInput`](crate::operation::delete_custom_routing_accelerator::DeleteCustomRoutingAcceleratorInput).
    pub fn builder() -> crate::operation::delete_custom_routing_accelerator::builders::DeleteCustomRoutingAcceleratorInputBuilder {
        crate::operation::delete_custom_routing_accelerator::builders::DeleteCustomRoutingAcceleratorInputBuilder::default()
    }
}

/// A builder for [`DeleteCustomRoutingAcceleratorInput`](crate::operation::delete_custom_routing_accelerator::DeleteCustomRoutingAcceleratorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCustomRoutingAcceleratorInputBuilder {
    pub(crate) accelerator_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteCustomRoutingAcceleratorInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the custom routing accelerator to delete.</p>
    /// This field is required.
    pub fn accelerator_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accelerator_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom routing accelerator to delete.</p>
    pub fn set_accelerator_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accelerator_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom routing accelerator to delete.</p>
    pub fn get_accelerator_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.accelerator_arn
    }
    /// Consumes the builder and constructs a [`DeleteCustomRoutingAcceleratorInput`](crate::operation::delete_custom_routing_accelerator::DeleteCustomRoutingAcceleratorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_custom_routing_accelerator::DeleteCustomRoutingAcceleratorInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_custom_routing_accelerator::DeleteCustomRoutingAcceleratorInput {
            accelerator_arn: self.accelerator_arn,
        })
    }
}
