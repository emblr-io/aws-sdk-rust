// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StateInfo {
    #[allow(missing_docs)] // documentation missing in model
    pub code: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::option::Option<::std::string::String>,
}
impl StateInfo {
    #[allow(missing_docs)] // documentation missing in model
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl StateInfo {
    /// Creates a new builder-style object to manufacture [`StateInfo`](crate::types::StateInfo).
    pub fn builder() -> crate::types::builders::StateInfoBuilder {
        crate::types::builders::StateInfoBuilder::default()
    }
}

/// A builder for [`StateInfo`](crate::types::StateInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StateInfoBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl StateInfoBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`StateInfo`](crate::types::StateInfo).
    pub fn build(self) -> crate::types::StateInfo {
        crate::types::StateInfo {
            code: self.code,
            message: self.message,
        }
    }
}
