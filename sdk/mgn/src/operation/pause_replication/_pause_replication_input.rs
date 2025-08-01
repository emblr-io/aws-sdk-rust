// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PauseReplicationInput {
    /// <p>Pause Replication Request source server ID.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Pause Replication Request account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl PauseReplicationInput {
    /// <p>Pause Replication Request source server ID.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Pause Replication Request account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl PauseReplicationInput {
    /// Creates a new builder-style object to manufacture [`PauseReplicationInput`](crate::operation::pause_replication::PauseReplicationInput).
    pub fn builder() -> crate::operation::pause_replication::builders::PauseReplicationInputBuilder {
        crate::operation::pause_replication::builders::PauseReplicationInputBuilder::default()
    }
}

/// A builder for [`PauseReplicationInput`](crate::operation::pause_replication::PauseReplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PauseReplicationInputBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl PauseReplicationInputBuilder {
    /// <p>Pause Replication Request source server ID.</p>
    /// This field is required.
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pause Replication Request source server ID.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>Pause Replication Request source server ID.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Pause Replication Request account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pause Replication Request account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Pause Replication Request account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`PauseReplicationInput`](crate::operation::pause_replication::PauseReplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::pause_replication::PauseReplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::pause_replication::PauseReplicationInput {
            source_server_id: self.source_server_id,
            account_id: self.account_id,
        })
    }
}
