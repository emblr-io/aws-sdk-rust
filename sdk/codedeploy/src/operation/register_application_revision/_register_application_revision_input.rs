// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a RegisterApplicationRevision operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterApplicationRevisionInput {
    /// <p>The name of an CodeDeploy application associated with the user or Amazon Web Services account.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>A comment about the revision.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Information about the application revision to register, including type and location.</p>
    pub revision: ::std::option::Option<crate::types::RevisionLocation>,
}
impl RegisterApplicationRevisionInput {
    /// <p>The name of an CodeDeploy application associated with the user or Amazon Web Services account.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>A comment about the revision.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Information about the application revision to register, including type and location.</p>
    pub fn revision(&self) -> ::std::option::Option<&crate::types::RevisionLocation> {
        self.revision.as_ref()
    }
}
impl RegisterApplicationRevisionInput {
    /// Creates a new builder-style object to manufacture [`RegisterApplicationRevisionInput`](crate::operation::register_application_revision::RegisterApplicationRevisionInput).
    pub fn builder() -> crate::operation::register_application_revision::builders::RegisterApplicationRevisionInputBuilder {
        crate::operation::register_application_revision::builders::RegisterApplicationRevisionInputBuilder::default()
    }
}

/// A builder for [`RegisterApplicationRevisionInput`](crate::operation::register_application_revision::RegisterApplicationRevisionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterApplicationRevisionInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) revision: ::std::option::Option<crate::types::RevisionLocation>,
}
impl RegisterApplicationRevisionInputBuilder {
    /// <p>The name of an CodeDeploy application associated with the user or Amazon Web Services account.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an CodeDeploy application associated with the user or Amazon Web Services account.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>The name of an CodeDeploy application associated with the user or Amazon Web Services account.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>A comment about the revision.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A comment about the revision.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A comment about the revision.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Information about the application revision to register, including type and location.</p>
    /// This field is required.
    pub fn revision(mut self, input: crate::types::RevisionLocation) -> Self {
        self.revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the application revision to register, including type and location.</p>
    pub fn set_revision(mut self, input: ::std::option::Option<crate::types::RevisionLocation>) -> Self {
        self.revision = input;
        self
    }
    /// <p>Information about the application revision to register, including type and location.</p>
    pub fn get_revision(&self) -> &::std::option::Option<crate::types::RevisionLocation> {
        &self.revision
    }
    /// Consumes the builder and constructs a [`RegisterApplicationRevisionInput`](crate::operation::register_application_revision::RegisterApplicationRevisionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::register_application_revision::RegisterApplicationRevisionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::register_application_revision::RegisterApplicationRevisionInput {
            application_name: self.application_name,
            description: self.description,
            revision: self.revision,
        })
    }
}
