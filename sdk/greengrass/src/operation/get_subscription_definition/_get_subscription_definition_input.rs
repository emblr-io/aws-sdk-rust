// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSubscriptionDefinitionInput {
    /// The ID of the subscription definition.
    pub subscription_definition_id: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionDefinitionInput {
    /// The ID of the subscription definition.
    pub fn subscription_definition_id(&self) -> ::std::option::Option<&str> {
        self.subscription_definition_id.as_deref()
    }
}
impl GetSubscriptionDefinitionInput {
    /// Creates a new builder-style object to manufacture [`GetSubscriptionDefinitionInput`](crate::operation::get_subscription_definition::GetSubscriptionDefinitionInput).
    pub fn builder() -> crate::operation::get_subscription_definition::builders::GetSubscriptionDefinitionInputBuilder {
        crate::operation::get_subscription_definition::builders::GetSubscriptionDefinitionInputBuilder::default()
    }
}

/// A builder for [`GetSubscriptionDefinitionInput`](crate::operation::get_subscription_definition::GetSubscriptionDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSubscriptionDefinitionInputBuilder {
    pub(crate) subscription_definition_id: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionDefinitionInputBuilder {
    /// The ID of the subscription definition.
    /// This field is required.
    pub fn subscription_definition_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_definition_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the subscription definition.
    pub fn set_subscription_definition_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_definition_id = input;
        self
    }
    /// The ID of the subscription definition.
    pub fn get_subscription_definition_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_definition_id
    }
    /// Consumes the builder and constructs a [`GetSubscriptionDefinitionInput`](crate::operation::get_subscription_definition::GetSubscriptionDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_subscription_definition::GetSubscriptionDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_subscription_definition::GetSubscriptionDefinitionInput {
            subscription_definition_id: self.subscription_definition_id,
        })
    }
}
