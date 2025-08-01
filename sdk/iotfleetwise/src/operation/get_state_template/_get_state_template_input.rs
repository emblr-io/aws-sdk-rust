// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStateTemplateInput {
    /// <p>The unique ID of the state template.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetStateTemplateInput {
    /// <p>The unique ID of the state template.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetStateTemplateInput {
    /// Creates a new builder-style object to manufacture [`GetStateTemplateInput`](crate::operation::get_state_template::GetStateTemplateInput).
    pub fn builder() -> crate::operation::get_state_template::builders::GetStateTemplateInputBuilder {
        crate::operation::get_state_template::builders::GetStateTemplateInputBuilder::default()
    }
}

/// A builder for [`GetStateTemplateInput`](crate::operation::get_state_template::GetStateTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStateTemplateInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetStateTemplateInputBuilder {
    /// <p>The unique ID of the state template.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the state template.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique ID of the state template.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetStateTemplateInput`](crate::operation::get_state_template::GetStateTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_state_template::GetStateTemplateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_state_template::GetStateTemplateInput { identifier: self.identifier })
    }
}
