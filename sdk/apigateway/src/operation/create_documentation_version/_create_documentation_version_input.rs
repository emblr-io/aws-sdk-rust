// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Creates a new documentation version of a given API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDocumentationVersionInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The version identifier of the new snapshot.</p>
    pub documentation_version: ::std::option::Option<::std::string::String>,
    /// <p>The stage name to be associated with the new documentation snapshot.</p>
    pub stage_name: ::std::option::Option<::std::string::String>,
    /// <p>A description about the new documentation snapshot.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl CreateDocumentationVersionInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The version identifier of the new snapshot.</p>
    pub fn documentation_version(&self) -> ::std::option::Option<&str> {
        self.documentation_version.as_deref()
    }
    /// <p>The stage name to be associated with the new documentation snapshot.</p>
    pub fn stage_name(&self) -> ::std::option::Option<&str> {
        self.stage_name.as_deref()
    }
    /// <p>A description about the new documentation snapshot.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl CreateDocumentationVersionInput {
    /// Creates a new builder-style object to manufacture [`CreateDocumentationVersionInput`](crate::operation::create_documentation_version::CreateDocumentationVersionInput).
    pub fn builder() -> crate::operation::create_documentation_version::builders::CreateDocumentationVersionInputBuilder {
        crate::operation::create_documentation_version::builders::CreateDocumentationVersionInputBuilder::default()
    }
}

/// A builder for [`CreateDocumentationVersionInput`](crate::operation::create_documentation_version::CreateDocumentationVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDocumentationVersionInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) documentation_version: ::std::option::Option<::std::string::String>,
    pub(crate) stage_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl CreateDocumentationVersionInputBuilder {
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The version identifier of the new snapshot.</p>
    /// This field is required.
    pub fn documentation_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.documentation_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version identifier of the new snapshot.</p>
    pub fn set_documentation_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.documentation_version = input;
        self
    }
    /// <p>The version identifier of the new snapshot.</p>
    pub fn get_documentation_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.documentation_version
    }
    /// <p>The stage name to be associated with the new documentation snapshot.</p>
    pub fn stage_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stage name to be associated with the new documentation snapshot.</p>
    pub fn set_stage_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage_name = input;
        self
    }
    /// <p>The stage name to be associated with the new documentation snapshot.</p>
    pub fn get_stage_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage_name
    }
    /// <p>A description about the new documentation snapshot.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description about the new documentation snapshot.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description about the new documentation snapshot.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`CreateDocumentationVersionInput`](crate::operation::create_documentation_version::CreateDocumentationVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_documentation_version::CreateDocumentationVersionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_documentation_version::CreateDocumentationVersionInput {
            rest_api_id: self.rest_api_id,
            documentation_version: self.documentation_version,
            stage_name: self.stage_name,
            description: self.description,
        })
    }
}
