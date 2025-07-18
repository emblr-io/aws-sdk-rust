// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Structure describing one Credential Locker.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CredentialLockerSummary {
    /// <p>The id of the credential locker.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the credential locker.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the credential locker.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The timestampe value of when the credential locker was created at.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CredentialLockerSummary {
    /// <p>The id of the credential locker.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the credential locker.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the credential locker.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The timestampe value of when the credential locker was created at.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
}
impl ::std::fmt::Debug for CredentialLockerSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CredentialLockerSummary");
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("created_at", &self.created_at);
        formatter.finish()
    }
}
impl CredentialLockerSummary {
    /// Creates a new builder-style object to manufacture [`CredentialLockerSummary`](crate::types::CredentialLockerSummary).
    pub fn builder() -> crate::types::builders::CredentialLockerSummaryBuilder {
        crate::types::builders::CredentialLockerSummaryBuilder::default()
    }
}

/// A builder for [`CredentialLockerSummary`](crate::types::CredentialLockerSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CredentialLockerSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CredentialLockerSummaryBuilder {
    /// <p>The id of the credential locker.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The id of the credential locker.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The id of the credential locker.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the credential locker.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the credential locker.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the credential locker.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the credential locker.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the credential locker.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the credential locker.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The timestampe value of when the credential locker was created at.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestampe value of when the credential locker was created at.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestampe value of when the credential locker was created at.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// Consumes the builder and constructs a [`CredentialLockerSummary`](crate::types::CredentialLockerSummary).
    pub fn build(self) -> crate::types::CredentialLockerSummary {
        crate::types::CredentialLockerSummary {
            id: self.id,
            arn: self.arn,
            name: self.name,
            created_at: self.created_at,
        }
    }
}
impl ::std::fmt::Debug for CredentialLockerSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CredentialLockerSummaryBuilder");
        formatter.field("id", &self.id);
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("created_at", &self.created_at);
        formatter.finish()
    }
}
