// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the name and version of a DataBrew recipe.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecipeReference {
    /// <p>The name of the recipe.</p>
    pub name: ::std::string::String,
    /// <p>The identifier for the version for the recipe.</p>
    pub recipe_version: ::std::option::Option<::std::string::String>,
}
impl RecipeReference {
    /// <p>The name of the recipe.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The identifier for the version for the recipe.</p>
    pub fn recipe_version(&self) -> ::std::option::Option<&str> {
        self.recipe_version.as_deref()
    }
}
impl RecipeReference {
    /// Creates a new builder-style object to manufacture [`RecipeReference`](crate::types::RecipeReference).
    pub fn builder() -> crate::types::builders::RecipeReferenceBuilder {
        crate::types::builders::RecipeReferenceBuilder::default()
    }
}

/// A builder for [`RecipeReference`](crate::types::RecipeReference).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecipeReferenceBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) recipe_version: ::std::option::Option<::std::string::String>,
}
impl RecipeReferenceBuilder {
    /// <p>The name of the recipe.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the recipe.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the recipe.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The identifier for the version for the recipe.</p>
    pub fn recipe_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipe_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the version for the recipe.</p>
    pub fn set_recipe_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipe_version = input;
        self
    }
    /// <p>The identifier for the version for the recipe.</p>
    pub fn get_recipe_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipe_version
    }
    /// Consumes the builder and constructs a [`RecipeReference`](crate::types::RecipeReference).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::RecipeReferenceBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::RecipeReference, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecipeReference {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building RecipeReference",
                )
            })?,
            recipe_version: self.recipe_version,
        })
    }
}
