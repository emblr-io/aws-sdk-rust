// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveProfilePermissionInput {
    /// <p>A human-readable name for the signing profile with permissions to be removed.</p>
    pub profile_name: ::std::option::Option<::std::string::String>,
    /// <p>An identifier for the current revision of the signing profile permissions.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the cross-account permissions statement.</p>
    pub statement_id: ::std::option::Option<::std::string::String>,
}
impl RemoveProfilePermissionInput {
    /// <p>A human-readable name for the signing profile with permissions to be removed.</p>
    pub fn profile_name(&self) -> ::std::option::Option<&str> {
        self.profile_name.as_deref()
    }
    /// <p>An identifier for the current revision of the signing profile permissions.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>A unique identifier for the cross-account permissions statement.</p>
    pub fn statement_id(&self) -> ::std::option::Option<&str> {
        self.statement_id.as_deref()
    }
}
impl RemoveProfilePermissionInput {
    /// Creates a new builder-style object to manufacture [`RemoveProfilePermissionInput`](crate::operation::remove_profile_permission::RemoveProfilePermissionInput).
    pub fn builder() -> crate::operation::remove_profile_permission::builders::RemoveProfilePermissionInputBuilder {
        crate::operation::remove_profile_permission::builders::RemoveProfilePermissionInputBuilder::default()
    }
}

/// A builder for [`RemoveProfilePermissionInput`](crate::operation::remove_profile_permission::RemoveProfilePermissionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveProfilePermissionInputBuilder {
    pub(crate) profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) statement_id: ::std::option::Option<::std::string::String>,
}
impl RemoveProfilePermissionInputBuilder {
    /// <p>A human-readable name for the signing profile with permissions to be removed.</p>
    /// This field is required.
    pub fn profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A human-readable name for the signing profile with permissions to be removed.</p>
    pub fn set_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_name = input;
        self
    }
    /// <p>A human-readable name for the signing profile with permissions to be removed.</p>
    pub fn get_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_name
    }
    /// <p>An identifier for the current revision of the signing profile permissions.</p>
    /// This field is required.
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for the current revision of the signing profile permissions.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>An identifier for the current revision of the signing profile permissions.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>A unique identifier for the cross-account permissions statement.</p>
    /// This field is required.
    pub fn statement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the cross-account permissions statement.</p>
    pub fn set_statement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_id = input;
        self
    }
    /// <p>A unique identifier for the cross-account permissions statement.</p>
    pub fn get_statement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_id
    }
    /// Consumes the builder and constructs a [`RemoveProfilePermissionInput`](crate::operation::remove_profile_permission::RemoveProfilePermissionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::remove_profile_permission::RemoveProfilePermissionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::remove_profile_permission::RemoveProfilePermissionInput {
            profile_name: self.profile_name,
            revision_id: self.revision_id,
            statement_id: self.statement_id,
        })
    }
}
