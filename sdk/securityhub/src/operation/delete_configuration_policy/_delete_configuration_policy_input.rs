// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConfigurationPolicyInput {
    /// <p>The Amazon Resource Name (ARN) or universally unique identifier (UUID) of the configuration policy.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationPolicyInput {
    /// <p>The Amazon Resource Name (ARN) or universally unique identifier (UUID) of the configuration policy.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl DeleteConfigurationPolicyInput {
    /// Creates a new builder-style object to manufacture [`DeleteConfigurationPolicyInput`](crate::operation::delete_configuration_policy::DeleteConfigurationPolicyInput).
    pub fn builder() -> crate::operation::delete_configuration_policy::builders::DeleteConfigurationPolicyInputBuilder {
        crate::operation::delete_configuration_policy::builders::DeleteConfigurationPolicyInputBuilder::default()
    }
}

/// A builder for [`DeleteConfigurationPolicyInput`](crate::operation::delete_configuration_policy::DeleteConfigurationPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConfigurationPolicyInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationPolicyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) or universally unique identifier (UUID) of the configuration policy.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or universally unique identifier (UUID) of the configuration policy.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or universally unique identifier (UUID) of the configuration policy.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`DeleteConfigurationPolicyInput`](crate::operation::delete_configuration_policy::DeleteConfigurationPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_configuration_policy::DeleteConfigurationPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_configuration_policy::DeleteConfigurationPolicyInput { identifier: self.identifier })
    }
}
