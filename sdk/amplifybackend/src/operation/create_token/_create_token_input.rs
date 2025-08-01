// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTokenInput {
    /// <p>The app ID.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
}
impl CreateTokenInput {
    /// <p>The app ID.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
}
impl CreateTokenInput {
    /// Creates a new builder-style object to manufacture [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
    pub fn builder() -> crate::operation::create_token::builders::CreateTokenInputBuilder {
        crate::operation::create_token::builders::CreateTokenInputBuilder::default()
    }
}

/// A builder for [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTokenInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
}
impl CreateTokenInputBuilder {
    /// <p>The app ID.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// Consumes the builder and constructs a [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_token::CreateTokenInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_token::CreateTokenInput { app_id: self.app_id })
    }
}
