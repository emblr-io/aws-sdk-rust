// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEventIntegrationInput {
    /// <p>The name of the event integration.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteEventIntegrationInput {
    /// <p>The name of the event integration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteEventIntegrationInput {
    /// Creates a new builder-style object to manufacture [`DeleteEventIntegrationInput`](crate::operation::delete_event_integration::DeleteEventIntegrationInput).
    pub fn builder() -> crate::operation::delete_event_integration::builders::DeleteEventIntegrationInputBuilder {
        crate::operation::delete_event_integration::builders::DeleteEventIntegrationInputBuilder::default()
    }
}

/// A builder for [`DeleteEventIntegrationInput`](crate::operation::delete_event_integration::DeleteEventIntegrationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEventIntegrationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteEventIntegrationInputBuilder {
    /// <p>The name of the event integration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the event integration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the event integration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteEventIntegrationInput`](crate::operation::delete_event_integration::DeleteEventIntegrationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_event_integration::DeleteEventIntegrationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_event_integration::DeleteEventIntegrationInput { name: self.name })
    }
}
