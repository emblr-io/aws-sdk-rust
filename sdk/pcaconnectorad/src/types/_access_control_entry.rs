// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An access control entry allows or denies Active Directory groups based on their security identifiers (SIDs) from enrolling and/or autoenrolling with the template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessControlEntry {
    /// <p>Name of the Active Directory group. This name does not need to match the group name in Active Directory.</p>
    pub group_display_name: ::std::option::Option<::std::string::String>,
    /// <p>Security identifier (SID) of the group object from Active Directory. The SID starts with "S-".</p>
    pub group_security_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Permissions to allow or deny an Active Directory group to enroll or autoenroll certificates issued against a template.</p>
    pub access_rights: ::std::option::Option<crate::types::AccessRights>,
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/pca-connector-ad/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a>.</p>
    pub template_arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the Access Control Entry was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the Access Control Entry was updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AccessControlEntry {
    /// <p>Name of the Active Directory group. This name does not need to match the group name in Active Directory.</p>
    pub fn group_display_name(&self) -> ::std::option::Option<&str> {
        self.group_display_name.as_deref()
    }
    /// <p>Security identifier (SID) of the group object from Active Directory. The SID starts with "S-".</p>
    pub fn group_security_identifier(&self) -> ::std::option::Option<&str> {
        self.group_security_identifier.as_deref()
    }
    /// <p>Permissions to allow or deny an Active Directory group to enroll or autoenroll certificates issued against a template.</p>
    pub fn access_rights(&self) -> ::std::option::Option<&crate::types::AccessRights> {
        self.access_rights.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/pca-connector-ad/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a>.</p>
    pub fn template_arn(&self) -> ::std::option::Option<&str> {
        self.template_arn.as_deref()
    }
    /// <p>The date and time that the Access Control Entry was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time that the Access Control Entry was updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
}
impl AccessControlEntry {
    /// Creates a new builder-style object to manufacture [`AccessControlEntry`](crate::types::AccessControlEntry).
    pub fn builder() -> crate::types::builders::AccessControlEntryBuilder {
        crate::types::builders::AccessControlEntryBuilder::default()
    }
}

/// A builder for [`AccessControlEntry`](crate::types::AccessControlEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessControlEntryBuilder {
    pub(crate) group_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) group_security_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) access_rights: ::std::option::Option<crate::types::AccessRights>,
    pub(crate) template_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AccessControlEntryBuilder {
    /// <p>Name of the Active Directory group. This name does not need to match the group name in Active Directory.</p>
    pub fn group_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the Active Directory group. This name does not need to match the group name in Active Directory.</p>
    pub fn set_group_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_display_name = input;
        self
    }
    /// <p>Name of the Active Directory group. This name does not need to match the group name in Active Directory.</p>
    pub fn get_group_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_display_name
    }
    /// <p>Security identifier (SID) of the group object from Active Directory. The SID starts with "S-".</p>
    pub fn group_security_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_security_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Security identifier (SID) of the group object from Active Directory. The SID starts with "S-".</p>
    pub fn set_group_security_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_security_identifier = input;
        self
    }
    /// <p>Security identifier (SID) of the group object from Active Directory. The SID starts with "S-".</p>
    pub fn get_group_security_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_security_identifier
    }
    /// <p>Permissions to allow or deny an Active Directory group to enroll or autoenroll certificates issued against a template.</p>
    pub fn access_rights(mut self, input: crate::types::AccessRights) -> Self {
        self.access_rights = ::std::option::Option::Some(input);
        self
    }
    /// <p>Permissions to allow or deny an Active Directory group to enroll or autoenroll certificates issued against a template.</p>
    pub fn set_access_rights(mut self, input: ::std::option::Option<crate::types::AccessRights>) -> Self {
        self.access_rights = input;
        self
    }
    /// <p>Permissions to allow or deny an Active Directory group to enroll or autoenroll certificates issued against a template.</p>
    pub fn get_access_rights(&self) -> &::std::option::Option<crate::types::AccessRights> {
        &self.access_rights
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/pca-connector-ad/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a>.</p>
    pub fn template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/pca-connector-ad/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a>.</p>
    pub fn set_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/pca-connector-ad/latest/APIReference/API_CreateTemplate.html">CreateTemplate</a>.</p>
    pub fn get_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_arn
    }
    /// <p>The date and time that the Access Control Entry was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the Access Control Entry was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the Access Control Entry was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time that the Access Control Entry was updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the Access Control Entry was updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time that the Access Control Entry was updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Consumes the builder and constructs a [`AccessControlEntry`](crate::types::AccessControlEntry).
    pub fn build(self) -> crate::types::AccessControlEntry {
        crate::types::AccessControlEntry {
            group_display_name: self.group_display_name,
            group_security_identifier: self.group_security_identifier,
            access_rights: self.access_rights,
            template_arn: self.template_arn,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
