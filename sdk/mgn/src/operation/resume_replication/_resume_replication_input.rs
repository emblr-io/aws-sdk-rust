// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResumeReplicationInput {
    /// <p>Resume Replication Request source server ID.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Resume Replication Request account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl ResumeReplicationInput {
    /// <p>Resume Replication Request source server ID.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Resume Replication Request account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl ResumeReplicationInput {
    /// Creates a new builder-style object to manufacture [`ResumeReplicationInput`](crate::operation::resume_replication::ResumeReplicationInput).
    pub fn builder() -> crate::operation::resume_replication::builders::ResumeReplicationInputBuilder {
        crate::operation::resume_replication::builders::ResumeReplicationInputBuilder::default()
    }
}

/// A builder for [`ResumeReplicationInput`](crate::operation::resume_replication::ResumeReplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResumeReplicationInputBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl ResumeReplicationInputBuilder {
    /// <p>Resume Replication Request source server ID.</p>
    /// This field is required.
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Resume Replication Request source server ID.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>Resume Replication Request source server ID.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Resume Replication Request account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Resume Replication Request account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Resume Replication Request account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`ResumeReplicationInput`](crate::operation::resume_replication::ResumeReplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::resume_replication::ResumeReplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::resume_replication::ResumeReplicationInput {
            source_server_id: self.source_server_id,
            account_id: self.account_id,
        })
    }
}
