// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCollectionInput {
    /// <p>The unique identifier of the collection. For example, <code>1iu5usc406kd</code>. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteCollectionInput {
    /// <p>The unique identifier of the collection. For example, <code>1iu5usc406kd</code>. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl DeleteCollectionInput {
    /// Creates a new builder-style object to manufacture [`DeleteCollectionInput`](crate::operation::delete_collection::DeleteCollectionInput).
    pub fn builder() -> crate::operation::delete_collection::builders::DeleteCollectionInputBuilder {
        crate::operation::delete_collection::builders::DeleteCollectionInputBuilder::default()
    }
}

/// A builder for [`DeleteCollectionInput`](crate::operation::delete_collection::DeleteCollectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCollectionInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl DeleteCollectionInputBuilder {
    /// <p>The unique identifier of the collection. For example, <code>1iu5usc406kd</code>. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the collection. For example, <code>1iu5usc406kd</code>. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the collection. For example, <code>1iu5usc406kd</code>. The ID is part of the collection endpoint. You can also retrieve it using the <a href="https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_ListCollections.html">ListCollections</a> API.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`DeleteCollectionInput`](crate::operation::delete_collection::DeleteCollectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_collection::DeleteCollectionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_collection::DeleteCollectionInput {
            id: self.id,
            client_token: self.client_token,
        })
    }
}
