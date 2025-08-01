// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProjectInput {
    /// <p>The name of the space.</p>
    pub space_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the project in the space.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl GetProjectInput {
    /// <p>The name of the space.</p>
    pub fn space_name(&self) -> ::std::option::Option<&str> {
        self.space_name.as_deref()
    }
    /// <p>The name of the project in the space.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl GetProjectInput {
    /// Creates a new builder-style object to manufacture [`GetProjectInput`](crate::operation::get_project::GetProjectInput).
    pub fn builder() -> crate::operation::get_project::builders::GetProjectInputBuilder {
        crate::operation::get_project::builders::GetProjectInputBuilder::default()
    }
}

/// A builder for [`GetProjectInput`](crate::operation::get_project::GetProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProjectInputBuilder {
    pub(crate) space_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl GetProjectInputBuilder {
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
    /// <p>The name of the project in the space.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the project in the space.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`GetProjectInput`](crate::operation::get_project::GetProjectInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_project::GetProjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_project::GetProjectInput {
            space_name: self.space_name,
            name: self.name,
        })
    }
}
