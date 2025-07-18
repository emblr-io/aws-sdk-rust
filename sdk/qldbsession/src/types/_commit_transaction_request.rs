// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of the transaction to commit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CommitTransactionRequest {
    /// <p>Specifies the transaction ID of the transaction to commit.</p>
    pub transaction_id: ::std::string::String,
    /// <p>Specifies the commit digest for the transaction to commit. For every active transaction, the commit digest must be passed. QLDB validates <code>CommitDigest</code> and rejects the commit with an error if the digest computed on the client does not match the digest computed by QLDB.</p>
    /// <p>The purpose of the <code>CommitDigest</code> parameter is to ensure that QLDB commits a transaction if and only if the server has processed the exact set of statements sent by the client, in the same order that client sent them, and with no duplicates.</p>
    pub commit_digest: ::aws_smithy_types::Blob,
}
impl CommitTransactionRequest {
    /// <p>Specifies the transaction ID of the transaction to commit.</p>
    pub fn transaction_id(&self) -> &str {
        use std::ops::Deref;
        self.transaction_id.deref()
    }
    /// <p>Specifies the commit digest for the transaction to commit. For every active transaction, the commit digest must be passed. QLDB validates <code>CommitDigest</code> and rejects the commit with an error if the digest computed on the client does not match the digest computed by QLDB.</p>
    /// <p>The purpose of the <code>CommitDigest</code> parameter is to ensure that QLDB commits a transaction if and only if the server has processed the exact set of statements sent by the client, in the same order that client sent them, and with no duplicates.</p>
    pub fn commit_digest(&self) -> &::aws_smithy_types::Blob {
        &self.commit_digest
    }
}
impl CommitTransactionRequest {
    /// Creates a new builder-style object to manufacture [`CommitTransactionRequest`](crate::types::CommitTransactionRequest).
    pub fn builder() -> crate::types::builders::CommitTransactionRequestBuilder {
        crate::types::builders::CommitTransactionRequestBuilder::default()
    }
}

/// A builder for [`CommitTransactionRequest`](crate::types::CommitTransactionRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommitTransactionRequestBuilder {
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
    pub(crate) commit_digest: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl CommitTransactionRequestBuilder {
    /// <p>Specifies the transaction ID of the transaction to commit.</p>
    /// This field is required.
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the transaction ID of the transaction to commit.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>Specifies the transaction ID of the transaction to commit.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    /// <p>Specifies the commit digest for the transaction to commit. For every active transaction, the commit digest must be passed. QLDB validates <code>CommitDigest</code> and rejects the commit with an error if the digest computed on the client does not match the digest computed by QLDB.</p>
    /// <p>The purpose of the <code>CommitDigest</code> parameter is to ensure that QLDB commits a transaction if and only if the server has processed the exact set of statements sent by the client, in the same order that client sent them, and with no duplicates.</p>
    /// This field is required.
    pub fn commit_digest(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.commit_digest = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the commit digest for the transaction to commit. For every active transaction, the commit digest must be passed. QLDB validates <code>CommitDigest</code> and rejects the commit with an error if the digest computed on the client does not match the digest computed by QLDB.</p>
    /// <p>The purpose of the <code>CommitDigest</code> parameter is to ensure that QLDB commits a transaction if and only if the server has processed the exact set of statements sent by the client, in the same order that client sent them, and with no duplicates.</p>
    pub fn set_commit_digest(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.commit_digest = input;
        self
    }
    /// <p>Specifies the commit digest for the transaction to commit. For every active transaction, the commit digest must be passed. QLDB validates <code>CommitDigest</code> and rejects the commit with an error if the digest computed on the client does not match the digest computed by QLDB.</p>
    /// <p>The purpose of the <code>CommitDigest</code> parameter is to ensure that QLDB commits a transaction if and only if the server has processed the exact set of statements sent by the client, in the same order that client sent them, and with no duplicates.</p>
    pub fn get_commit_digest(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.commit_digest
    }
    /// Consumes the builder and constructs a [`CommitTransactionRequest`](crate::types::CommitTransactionRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`transaction_id`](crate::types::builders::CommitTransactionRequestBuilder::transaction_id)
    /// - [`commit_digest`](crate::types::builders::CommitTransactionRequestBuilder::commit_digest)
    pub fn build(self) -> ::std::result::Result<crate::types::CommitTransactionRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CommitTransactionRequest {
            transaction_id: self.transaction_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transaction_id",
                    "transaction_id was not specified but it is required when building CommitTransactionRequest",
                )
            })?,
            commit_digest: self.commit_digest.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "commit_digest",
                    "commit_digest was not specified but it is required when building CommitTransactionRequest",
                )
            })?,
        })
    }
}
