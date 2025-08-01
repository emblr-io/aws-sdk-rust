// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSpaceInput {
    /// <p>The name of the space.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl GetSpaceInput {
    /// <p>The name of the space.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl GetSpaceInput {
    /// Creates a new builder-style object to manufacture [`GetSpaceInput`](crate::operation::get_space::GetSpaceInput).
    pub fn builder() -> crate::operation::get_space::builders::GetSpaceInputBuilder {
        crate::operation::get_space::builders::GetSpaceInputBuilder::default()
    }
}

/// A builder for [`GetSpaceInput`](crate::operation::get_space::GetSpaceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSpaceInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl GetSpaceInputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`GetSpaceInput`](crate::operation::get_space::GetSpaceInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_space::GetSpaceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_space::GetSpaceInput { name: self.name })
    }
}
