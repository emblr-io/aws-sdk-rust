// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDistributionConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that you want to retrieve.</p>
    pub distribution_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl GetDistributionConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that you want to retrieve.</p>
    pub fn distribution_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.distribution_configuration_arn.as_deref()
    }
}
impl GetDistributionConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetDistributionConfigurationInput`](crate::operation::get_distribution_configuration::GetDistributionConfigurationInput).
    pub fn builder() -> crate::operation::get_distribution_configuration::builders::GetDistributionConfigurationInputBuilder {
        crate::operation::get_distribution_configuration::builders::GetDistributionConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetDistributionConfigurationInput`](crate::operation::get_distribution_configuration::GetDistributionConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDistributionConfigurationInputBuilder {
    pub(crate) distribution_configuration_arn: ::std::option::Option<::std::string::String>,
}
impl GetDistributionConfigurationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that you want to retrieve.</p>
    /// This field is required.
    pub fn distribution_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.distribution_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that you want to retrieve.</p>
    pub fn set_distribution_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.distribution_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the distribution configuration that you want to retrieve.</p>
    pub fn get_distribution_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.distribution_configuration_arn
    }
    /// Consumes the builder and constructs a [`GetDistributionConfigurationInput`](crate::operation::get_distribution_configuration::GetDistributionConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_distribution_configuration::GetDistributionConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_distribution_configuration::GetDistributionConfigurationInput {
            distribution_configuration_arn: self.distribution_configuration_arn,
        })
    }
}
