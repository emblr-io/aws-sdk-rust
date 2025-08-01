// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateProjectInput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the project.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the project.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> ::std::option::Option<&str> {
        self.space_name.as_deref()
    }
    /// <p>The name of the project.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the project.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateProjectInput {
    /// Creates a new builder-style object to manufacture [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn builder() -> crate::operation::update_project::builders::UpdateProjectInputBuilder {
        crate::operation::update_project::builders::UpdateProjectInputBuilder::default()
    }
}

/// A builder for [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateProjectInputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInputBuilder {
    /// <p>The name of the space.</p>
    /// This field is required.
    pub fn space_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.space_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the space.</p>
    pub fn set_space_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.space_name = input;
        self
    }
    /// <p>The name of the space.</p>
    pub fn get_space_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.space_name
    }
    /// <p>The name of the project.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the project.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the project.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the project.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the project.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_project::UpdateProjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_project::UpdateProjectInput {
            space_name: self.space_name,
            name: self.name,
            description: self.description,
        })
    }
}
