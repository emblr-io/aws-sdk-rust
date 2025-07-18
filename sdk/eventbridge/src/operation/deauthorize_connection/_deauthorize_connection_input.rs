// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeauthorizeConnectionInput {
    /// <p>The name of the connection to remove authorization from.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeauthorizeConnectionInput {
    /// <p>The name of the connection to remove authorization from.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeauthorizeConnectionInput {
    /// Creates a new builder-style object to manufacture [`DeauthorizeConnectionInput`](crate::operation::deauthorize_connection::DeauthorizeConnectionInput).
    pub fn builder() -> crate::operation::deauthorize_connection::builders::DeauthorizeConnectionInputBuilder {
        crate::operation::deauthorize_connection::builders::DeauthorizeConnectionInputBuilder::default()
    }
}

/// A builder for [`DeauthorizeConnectionInput`](crate::operation::deauthorize_connection::DeauthorizeConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeauthorizeConnectionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeauthorizeConnectionInputBuilder {
    /// <p>The name of the connection to remove authorization from.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connection to remove authorization from.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the connection to remove authorization from.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeauthorizeConnectionInput`](crate::operation::deauthorize_connection::DeauthorizeConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::deauthorize_connection::DeauthorizeConnectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::deauthorize_connection::DeauthorizeConnectionInput { name: self.name })
    }
}
