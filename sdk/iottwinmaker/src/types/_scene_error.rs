// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The scene error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SceneError {
    /// <p>The SceneError code.</p>
    pub code: ::std::option::Option<crate::types::SceneErrorCode>,
    /// <p>The SceneError message.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl SceneError {
    /// <p>The SceneError code.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::SceneErrorCode> {
        self.code.as_ref()
    }
    /// <p>The SceneError message.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl SceneError {
    /// Creates a new builder-style object to manufacture [`SceneError`](crate::types::SceneError).
    pub fn builder() -> crate::types::builders::SceneErrorBuilder {
        crate::types::builders::SceneErrorBuilder::default()
    }
}

/// A builder for [`SceneError`](crate::types::SceneError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SceneErrorBuilder {
    pub(crate) code: ::std::option::Option<crate::types::SceneErrorCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl SceneErrorBuilder {
    /// <p>The SceneError code.</p>
    pub fn code(mut self, input: crate::types::SceneErrorCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The SceneError code.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::SceneErrorCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The SceneError code.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::SceneErrorCode> {
        &self.code
    }
    /// <p>The SceneError message.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SceneError message.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The SceneError message.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`SceneError`](crate::types::SceneError).
    pub fn build(self) -> crate::types::SceneError {
        crate::types::SceneError {
            code: self.code,
            message: self.message,
        }
    }
}
