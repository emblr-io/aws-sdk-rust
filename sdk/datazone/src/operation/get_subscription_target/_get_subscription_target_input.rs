// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSubscriptionTargetInput {
    /// <p>The ID of the Amazon DataZone domain in which the subscription target exists.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the environment associated with the subscription target.</p>
    pub environment_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subscription target.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionTargetInput {
    /// <p>The ID of the Amazon DataZone domain in which the subscription target exists.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The ID of the environment associated with the subscription target.</p>
    pub fn environment_identifier(&self) -> ::std::option::Option<&str> {
        self.environment_identifier.as_deref()
    }
    /// <p>The ID of the subscription target.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetSubscriptionTargetInput {
    /// Creates a new builder-style object to manufacture [`GetSubscriptionTargetInput`](crate::operation::get_subscription_target::GetSubscriptionTargetInput).
    pub fn builder() -> crate::operation::get_subscription_target::builders::GetSubscriptionTargetInputBuilder {
        crate::operation::get_subscription_target::builders::GetSubscriptionTargetInputBuilder::default()
    }
}

/// A builder for [`GetSubscriptionTargetInput`](crate::operation::get_subscription_target::GetSubscriptionTargetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSubscriptionTargetInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) environment_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionTargetInputBuilder {
    /// <p>The ID of the Amazon DataZone domain in which the subscription target exists.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the subscription target exists.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which the subscription target exists.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The ID of the environment associated with the subscription target.</p>
    /// This field is required.
    pub fn environment_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the environment associated with the subscription target.</p>
    pub fn set_environment_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_identifier = input;
        self
    }
    /// <p>The ID of the environment associated with the subscription target.</p>
    pub fn get_environment_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_identifier
    }
    /// <p>The ID of the subscription target.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subscription target.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The ID of the subscription target.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetSubscriptionTargetInput`](crate::operation::get_subscription_target::GetSubscriptionTargetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_subscription_target::GetSubscriptionTargetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_subscription_target::GetSubscriptionTargetInput {
            domain_identifier: self.domain_identifier,
            environment_identifier: self.environment_identifier,
            identifier: self.identifier,
        })
    }
}
