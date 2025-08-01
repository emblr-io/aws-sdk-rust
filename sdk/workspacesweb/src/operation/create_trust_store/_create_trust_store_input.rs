// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTrustStoreInput {
    /// <p>A list of CA certificates to be added to the trust store.</p>
    pub certificate_list: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>,
    /// <p>The tags to add to the trust store. A tag is a key-value pair.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, subsequent retries with the same client token returns the result from the original successful request.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateTrustStoreInput {
    /// <p>A list of CA certificates to be added to the trust store.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.certificate_list.is_none()`.
    pub fn certificate_list(&self) -> &[::aws_smithy_types::Blob] {
        self.certificate_list.as_deref().unwrap_or_default()
    }
    /// <p>The tags to add to the trust store. A tag is a key-value pair.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, subsequent retries with the same client token returns the result from the original successful request.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateTrustStoreInput {
    /// Creates a new builder-style object to manufacture [`CreateTrustStoreInput`](crate::operation::create_trust_store::CreateTrustStoreInput).
    pub fn builder() -> crate::operation::create_trust_store::builders::CreateTrustStoreInputBuilder {
        crate::operation::create_trust_store::builders::CreateTrustStoreInputBuilder::default()
    }
}

/// A builder for [`CreateTrustStoreInput`](crate::operation::create_trust_store::CreateTrustStoreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTrustStoreInputBuilder {
    pub(crate) certificate_list: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateTrustStoreInputBuilder {
    /// Appends an item to `certificate_list`.
    ///
    /// To override the contents of this collection use [`set_certificate_list`](Self::set_certificate_list).
    ///
    /// <p>A list of CA certificates to be added to the trust store.</p>
    pub fn certificate_list(mut self, input: ::aws_smithy_types::Blob) -> Self {
        let mut v = self.certificate_list.unwrap_or_default();
        v.push(input);
        self.certificate_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of CA certificates to be added to the trust store.</p>
    pub fn set_certificate_list(mut self, input: ::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>>) -> Self {
        self.certificate_list = input;
        self
    }
    /// <p>A list of CA certificates to be added to the trust store.</p>
    pub fn get_certificate_list(&self) -> &::std::option::Option<::std::vec::Vec<::aws_smithy_types::Blob>> {
        &self.certificate_list
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to add to the trust store. A tag is a key-value pair.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to add to the trust store. A tag is a key-value pair.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to add to the trust store. A tag is a key-value pair.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, subsequent retries with the same client token returns the result from the original successful request.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, subsequent retries with the same client token returns the result from the original successful request.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully, subsequent retries with the same client token returns the result from the original successful request.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateTrustStoreInput`](crate::operation::create_trust_store::CreateTrustStoreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_trust_store::CreateTrustStoreInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_trust_store::CreateTrustStoreInput {
            certificate_list: self.certificate_list,
            tags: self.tags,
            client_token: self.client_token,
        })
    }
}
