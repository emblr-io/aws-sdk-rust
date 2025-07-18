// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeModelInput {
    /// <p>The name of the machine learning model to be described.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
}
impl DescribeModelInput {
    /// <p>The name of the machine learning model to be described.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
}
impl DescribeModelInput {
    /// Creates a new builder-style object to manufacture [`DescribeModelInput`](crate::operation::describe_model::DescribeModelInput).
    pub fn builder() -> crate::operation::describe_model::builders::DescribeModelInputBuilder {
        crate::operation::describe_model::builders::DescribeModelInputBuilder::default()
    }
}

/// A builder for [`DescribeModelInput`](crate::operation::describe_model::DescribeModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeModelInputBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
}
impl DescribeModelInputBuilder {
    /// <p>The name of the machine learning model to be described.</p>
    /// This field is required.
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the machine learning model to be described.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the machine learning model to be described.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// Consumes the builder and constructs a [`DescribeModelInput`](crate::operation::describe_model::DescribeModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_model::DescribeModelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_model::DescribeModelInput { model_name: self.model_name })
    }
}
