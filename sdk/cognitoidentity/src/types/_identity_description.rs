// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A description of the identity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdentityDescription {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub identity_id: ::std::option::Option<::std::string::String>,
    /// <p>The provider names.</p>
    pub logins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Date on which the identity was created.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Date on which the identity was last modified.</p>
    pub last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl IdentityDescription {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn identity_id(&self) -> ::std::option::Option<&str> {
        self.identity_id.as_deref()
    }
    /// <p>The provider names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.logins.is_none()`.
    pub fn logins(&self) -> &[::std::string::String] {
        self.logins.as_deref().unwrap_or_default()
    }
    /// <p>Date on which the identity was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>Date on which the identity was last modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_date.as_ref()
    }
}
impl IdentityDescription {
    /// Creates a new builder-style object to manufacture [`IdentityDescription`](crate::types::IdentityDescription).
    pub fn builder() -> crate::types::builders::IdentityDescriptionBuilder {
        crate::types::builders::IdentityDescriptionBuilder::default()
    }
}

/// A builder for [`IdentityDescription`](crate::types::IdentityDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdentityDescriptionBuilder {
    pub(crate) identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) logins: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl IdentityDescriptionBuilder {
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn set_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_id = input;
        self
    }
    /// <p>A unique identifier in the format REGION:GUID.</p>
    pub fn get_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_id
    }
    /// Appends an item to `logins`.
    ///
    /// To override the contents of this collection use [`set_logins`](Self::set_logins).
    ///
    /// <p>The provider names.</p>
    pub fn logins(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.logins.unwrap_or_default();
        v.push(input.into());
        self.logins = ::std::option::Option::Some(v);
        self
    }
    /// <p>The provider names.</p>
    pub fn set_logins(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.logins = input;
        self
    }
    /// <p>The provider names.</p>
    pub fn get_logins(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.logins
    }
    /// <p>Date on which the identity was created.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date on which the identity was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>Date on which the identity was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>Date on which the identity was last modified.</p>
    pub fn last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Date on which the identity was last modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>Date on which the identity was last modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_date
    }
    /// Consumes the builder and constructs a [`IdentityDescription`](crate::types::IdentityDescription).
    pub fn build(self) -> crate::types::IdentityDescription {
        crate::types::IdentityDescription {
            identity_id: self.identity_id,
            logins: self.logins,
            creation_date: self.creation_date,
            last_modified_date: self.last_modified_date,
        }
    }
}
