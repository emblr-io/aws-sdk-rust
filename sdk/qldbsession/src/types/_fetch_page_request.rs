// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the details of the page to be fetched.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FetchPageRequest {
    /// <p>Specifies the transaction ID of the page to be fetched.</p>
    pub transaction_id: ::std::string::String,
    /// <p>Specifies the next page token of the page to be fetched.</p>
    pub next_page_token: ::std::string::String,
}
impl FetchPageRequest {
    /// <p>Specifies the transaction ID of the page to be fetched.</p>
    pub fn transaction_id(&self) -> &str {
        use std::ops::Deref;
        self.transaction_id.deref()
    }
    /// <p>Specifies the next page token of the page to be fetched.</p>
    pub fn next_page_token(&self) -> &str {
        use std::ops::Deref;
        self.next_page_token.deref()
    }
}
impl FetchPageRequest {
    /// Creates a new builder-style object to manufacture [`FetchPageRequest`](crate::types::FetchPageRequest).
    pub fn builder() -> crate::types::builders::FetchPageRequestBuilder {
        crate::types::builders::FetchPageRequestBuilder::default()
    }
}

/// A builder for [`FetchPageRequest`](crate::types::FetchPageRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FetchPageRequestBuilder {
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
}
impl FetchPageRequestBuilder {
    /// <p>Specifies the transaction ID of the page to be fetched.</p>
    /// This field is required.
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the transaction ID of the page to be fetched.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>Specifies the transaction ID of the page to be fetched.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    /// <p>Specifies the next page token of the page to be fetched.</p>
    /// This field is required.
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the next page token of the page to be fetched.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>Specifies the next page token of the page to be fetched.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    /// Consumes the builder and constructs a [`FetchPageRequest`](crate::types::FetchPageRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`transaction_id`](crate::types::builders::FetchPageRequestBuilder::transaction_id)
    /// - [`next_page_token`](crate::types::builders::FetchPageRequestBuilder::next_page_token)
    pub fn build(self) -> ::std::result::Result<crate::types::FetchPageRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FetchPageRequest {
            transaction_id: self.transaction_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transaction_id",
                    "transaction_id was not specified but it is required when building FetchPageRequest",
                )
            })?,
            next_page_token: self.next_page_token.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "next_page_token",
                    "next_page_token was not specified but it is required when building FetchPageRequest",
                )
            })?,
        })
    }
}
