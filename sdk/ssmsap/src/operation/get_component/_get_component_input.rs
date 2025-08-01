// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetComponentInput {
    /// <p>The ID of the application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the component.</p>
    pub component_id: ::std::option::Option<::std::string::String>,
}
impl GetComponentInput {
    /// <p>The ID of the application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The ID of the component.</p>
    pub fn component_id(&self) -> ::std::option::Option<&str> {
        self.component_id.as_deref()
    }
}
impl GetComponentInput {
    /// Creates a new builder-style object to manufacture [`GetComponentInput`](crate::operation::get_component::GetComponentInput).
    pub fn builder() -> crate::operation::get_component::builders::GetComponentInputBuilder {
        crate::operation::get_component::builders::GetComponentInputBuilder::default()
    }
}

/// A builder for [`GetComponentInput`](crate::operation::get_component::GetComponentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetComponentInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) component_id: ::std::option::Option<::std::string::String>,
}
impl GetComponentInputBuilder {
    /// <p>The ID of the application.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The ID of the application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The ID of the component.</p>
    /// This field is required.
    pub fn component_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the component.</p>
    pub fn set_component_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_id = input;
        self
    }
    /// <p>The ID of the component.</p>
    pub fn get_component_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_id
    }
    /// Consumes the builder and constructs a [`GetComponentInput`](crate::operation::get_component::GetComponentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_component::GetComponentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_component::GetComponentInput {
            application_id: self.application_id,
            component_id: self.component_id,
        })
    }
}
