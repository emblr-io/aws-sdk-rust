// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRecipeInput {
    /// <p>The name of the recipe to be described.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The recipe version identifier. If this parameter isn't specified, then the latest published version is returned.</p>
    pub recipe_version: ::std::option::Option<::std::string::String>,
}
impl DescribeRecipeInput {
    /// <p>The name of the recipe to be described.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The recipe version identifier. If this parameter isn't specified, then the latest published version is returned.</p>
    pub fn recipe_version(&self) -> ::std::option::Option<&str> {
        self.recipe_version.as_deref()
    }
}
impl DescribeRecipeInput {
    /// Creates a new builder-style object to manufacture [`DescribeRecipeInput`](crate::operation::describe_recipe::DescribeRecipeInput).
    pub fn builder() -> crate::operation::describe_recipe::builders::DescribeRecipeInputBuilder {
        crate::operation::describe_recipe::builders::DescribeRecipeInputBuilder::default()
    }
}

/// A builder for [`DescribeRecipeInput`](crate::operation::describe_recipe::DescribeRecipeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRecipeInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) recipe_version: ::std::option::Option<::std::string::String>,
}
impl DescribeRecipeInputBuilder {
    /// <p>The name of the recipe to be described.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the recipe to be described.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the recipe to be described.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The recipe version identifier. If this parameter isn't specified, then the latest published version is returned.</p>
    pub fn recipe_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recipe_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recipe version identifier. If this parameter isn't specified, then the latest published version is returned.</p>
    pub fn set_recipe_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recipe_version = input;
        self
    }
    /// <p>The recipe version identifier. If this parameter isn't specified, then the latest published version is returned.</p>
    pub fn get_recipe_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.recipe_version
    }
    /// Consumes the builder and constructs a [`DescribeRecipeInput`](crate::operation::describe_recipe::DescribeRecipeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_recipe::DescribeRecipeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_recipe::DescribeRecipeInput {
            name: self.name,
            recipe_version: self.recipe_version,
        })
    }
}
