// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLanguageModelInput {
    /// <p>The name of the custom language model you want information about. Model names are case sensitive.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLanguageModelInput {
    /// <p>The name of the custom language model you want information about. Model names are case sensitive.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
}
impl DescribeLanguageModelInput {
    /// Creates a new builder-style object to manufacture [`DescribeLanguageModelInput`](crate::operation::describe_language_model::DescribeLanguageModelInput).
    pub fn builder() -> crate::operation::describe_language_model::builders::DescribeLanguageModelInputBuilder {
        crate::operation::describe_language_model::builders::DescribeLanguageModelInputBuilder::default()
    }
}

/// A builder for [`DescribeLanguageModelInput`](crate::operation::describe_language_model::DescribeLanguageModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLanguageModelInputBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
}
impl DescribeLanguageModelInputBuilder {
    /// <p>The name of the custom language model you want information about. Model names are case sensitive.</p>
    /// This field is required.
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom language model you want information about. Model names are case sensitive.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the custom language model you want information about. Model names are case sensitive.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// Consumes the builder and constructs a [`DescribeLanguageModelInput`](crate::operation::describe_language_model::DescribeLanguageModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_language_model::DescribeLanguageModelInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_language_model::DescribeLanguageModelInput { model_name: self.model_name })
    }
}
