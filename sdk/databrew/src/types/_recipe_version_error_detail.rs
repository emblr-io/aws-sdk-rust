// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents any errors encountered when attempting to delete multiple recipe versions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecipeVersionErrorDetail {
    /// <p>The HTTP status code for the error.</p>
    pub error_code: ::std::option::Option<::std::string::String>,
    /// <p>The text of the error message.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the recipe version associated with this error.</p>
    pub recipe_version: ::std::option::Option<::std::string::String>,
}
impl RecipeVersionErrorDetail {
    /// <p>The HTTP status code for the error.</p>
    pub fn error_code(&self) -> ::std::option::Option<&str> {
        self.error_code.as_deref()
    }
    /// <p>The text of the error message.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The identifier for the recipe version associated with this error.</p>
    pub fn recipe_version(&self) -> ::std::option::Option<&str> {
        self.recipe_version.as_deref()
    }
}
impl RecipeVersionErrorDetail {
    /// Creates a new builder-style object to manufacture [`RecipeVersionErrorDetail`](crate::types::RecipeVersionErrorDetail).
    pub fn builder() -> crate::types::builders::RecipeVersionErrorDetailBuilder {
        crate::types::builders::RecipeVersionErrorDetailBuilder::default()
    }
}

/// A builder for [`RecipeVersionErrorDetail`](crate::types::RecipeVersionErrorDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecipeVersionErrorDetailBuilder {
    pub(crate) error_code: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) recipe_version: ::std::option::Option<::std::string::String>,
}
impl RecipeVersionErrorDetailBuilder {
    /// <p>The HTTP status code for the error.</p>
    pub fn error_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP status code for the error.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The HTTP status code for the error.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_code
    }
    /// <p>The text of the error message.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text of the error message.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The text of the error message.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>The identifier for the recipe version associated with this error.</p>
    pub fn recipe_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipe_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the recipe version associated with this error.</p>
    pub fn set_recipe_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipe_version = input;
        self
    }
    /// <p>The identifier for the recipe version associated with this error.</p>
    pub fn get_recipe_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipe_version
    }
    /// Consumes the builder and constructs a [`RecipeVersionErrorDetail`](crate::types::RecipeVersionErrorDetail).
    pub fn build(self) -> crate::types::RecipeVersionErrorDetail {
        crate::types::RecipeVersionErrorDetail {
            error_code: self.error_code,
            error_message: self.error_message,
            recipe_version: self.recipe_version,
        }
    }
}
