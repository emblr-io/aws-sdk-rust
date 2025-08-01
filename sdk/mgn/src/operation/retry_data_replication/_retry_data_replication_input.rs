// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetryDataReplicationInput {
    /// <p>Retry data replication for Source Server ID.</p>
    pub source_server_id: ::std::option::Option<::std::string::String>,
    /// <p>Retry data replication for Account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl RetryDataReplicationInput {
    /// <p>Retry data replication for Source Server ID.</p>
    pub fn source_server_id(&self) -> ::std::option::Option<&str> {
        self.source_server_id.as_deref()
    }
    /// <p>Retry data replication for Account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl RetryDataReplicationInput {
    /// Creates a new builder-style object to manufacture [`RetryDataReplicationInput`](crate::operation::retry_data_replication::RetryDataReplicationInput).
    pub fn builder() -> crate::operation::retry_data_replication::builders::RetryDataReplicationInputBuilder {
        crate::operation::retry_data_replication::builders::RetryDataReplicationInputBuilder::default()
    }
}

/// A builder for [`RetryDataReplicationInput`](crate::operation::retry_data_replication::RetryDataReplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetryDataReplicationInputBuilder {
    pub(crate) source_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl RetryDataReplicationInputBuilder {
    /// <p>Retry data replication for Source Server ID.</p>
    /// This field is required.
    pub fn source_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Retry data replication for Source Server ID.</p>
    pub fn set_source_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_server_id = input;
        self
    }
    /// <p>Retry data replication for Source Server ID.</p>
    pub fn get_source_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_server_id
    }
    /// <p>Retry data replication for Account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Retry data replication for Account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Retry data replication for Account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`RetryDataReplicationInput`](crate::operation::retry_data_replication::RetryDataReplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::retry_data_replication::RetryDataReplicationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::retry_data_replication::RetryDataReplicationInput {
            source_server_id: self.source_server_id,
            account_id: self.account_id,
        })
    }
}
