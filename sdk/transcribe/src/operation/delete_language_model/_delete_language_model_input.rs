// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLanguageModelInput {
    /// <p>The name of the custom language model you want to delete. Model names are case sensitive.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
}
impl DeleteLanguageModelInput {
    /// <p>The name of the custom language model you want to delete. Model names are case sensitive.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
}
impl DeleteLanguageModelInput {
    /// Creates a new builder-style object to manufacture [`DeleteLanguageModelInput`](crate::operation::delete_language_model::DeleteLanguageModelInput).
    pub fn builder() -> crate::operation::delete_language_model::builders::DeleteLanguageModelInputBuilder {
        crate::operation::delete_language_model::builders::DeleteLanguageModelInputBuilder::default()
    }
}

/// A builder for [`DeleteLanguageModelInput`](crate::operation::delete_language_model::DeleteLanguageModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLanguageModelInputBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
}
impl DeleteLanguageModelInputBuilder {
    /// <p>The name of the custom language model you want to delete. Model names are case sensitive.</p>
    /// This field is required.
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom language model you want to delete. Model names are case sensitive.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the custom language model you want to delete. Model names are case sensitive.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// Consumes the builder and constructs a [`DeleteLanguageModelInput`](crate::operation::delete_language_model::DeleteLanguageModelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_language_model::DeleteLanguageModelInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_language_model::DeleteLanguageModelInput { model_name: self.model_name })
    }
}
