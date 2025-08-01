// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReplicationInput {
    /// <p>ID of source server on which to start replication.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Account ID on which to start replication.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl StartReplicationInput {
    /// <p>ID of source server on which to start replication.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Account ID on which to start replication.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl StartReplicationInput {
    /// Creates a new builder-style object to manufacture [`StartReplicationInput`](crate::operation::start_replication::StartReplicationInput).
    pub fn builder() -> crate::operation::start_replication::builders::StartReplicationInputBuilder {
        crate::operation::start_replication::builders::StartReplicationInputBuilder::default()
    }
}

/// A builder for [`StartReplicationInput`](crate::operation::start_replication::StartReplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReplicationInputBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl StartReplicationInputBuilder {
    /// <p>ID of source server on which to start replication.</p>
    /// This field is required.
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of source server on which to start replication.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>ID of source server on which to start replication.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Account ID on which to start replication.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Account ID on which to start replication.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Account ID on which to start replication.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`StartReplicationInput`](crate::operation::start_replication::StartReplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_replication::StartReplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_replication::StartReplicationInput {
            source_server_id: self.source_server_id,
            account_id: self.account_id,
        })
    }
}
