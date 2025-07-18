// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PublishRecipeInput {
    /// <p>A description of the recipe to be published, for this version of the recipe.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The name of the recipe to be published.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl PublishRecipeInput {
    /// <p>A description of the recipe to be published, for this version of the recipe.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The name of the recipe to be published.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl PublishRecipeInput {
    /// Creates a new builder-style object to manufacture [`PublishRecipeInput`](crate::operation::publish_recipe::PublishRecipeInput).
    pub fn builder() -> crate::operation::publish_recipe::builders::PublishRecipeInputBuilder {
        crate::operation::publish_recipe::builders::PublishRecipeInputBuilder::default()
    }
}

/// A builder for [`PublishRecipeInput`](crate::operation::publish_recipe::PublishRecipeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PublishRecipeInputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl PublishRecipeInputBuilder {
    /// <p>A description of the recipe to be published, for this version of the recipe.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the recipe to be published, for this version of the recipe.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the recipe to be published, for this version of the recipe.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The name of the recipe to be published.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the recipe to be published.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the recipe to be published.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`PublishRecipeInput`](crate::operation::publish_recipe::PublishRecipeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::publish_recipe::PublishRecipeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::publish_recipe::PublishRecipeInput {
            description: self.description,
            name: self.name,
        })
    }
}
