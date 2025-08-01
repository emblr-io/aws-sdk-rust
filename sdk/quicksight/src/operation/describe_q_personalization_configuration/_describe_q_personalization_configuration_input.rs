// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeQPersonalizationConfigurationInput {
    /// <p>The ID of the Amazon Web Services account that contains the personalization configuration that the user wants described.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
}
impl DescribeQPersonalizationConfigurationInput {
    /// <p>The ID of the Amazon Web Services account that contains the personalization configuration that the user wants described.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
}
impl DescribeQPersonalizationConfigurationInput {
    /// Creates a new builder-style object to manufacture [`DescribeQPersonalizationConfigurationInput`](crate::operation::describe_q_personalization_configuration::DescribeQPersonalizationConfigurationInput).
    pub fn builder() -> crate::operation::describe_q_personalization_configuration::builders::DescribeQPersonalizationConfigurationInputBuilder {
        crate::operation::describe_q_personalization_configuration::builders::DescribeQPersonalizationConfigurationInputBuilder::default()
    }
}

/// A builder for [`DescribeQPersonalizationConfigurationInput`](crate::operation::describe_q_personalization_configuration::DescribeQPersonalizationConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeQPersonalizationConfigurationInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
}
impl DescribeQPersonalizationConfigurationInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the personalization configuration that the user wants described.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the personalization configuration that the user wants described.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the personalization configuration that the user wants described.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// Consumes the builder and constructs a [`DescribeQPersonalizationConfigurationInput`](crate::operation::describe_q_personalization_configuration::DescribeQPersonalizationConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_q_personalization_configuration::DescribeQPersonalizationConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_q_personalization_configuration::DescribeQPersonalizationConfigurationInput {
                aws_account_id: self.aws_account_id,
            },
        )
    }
}
