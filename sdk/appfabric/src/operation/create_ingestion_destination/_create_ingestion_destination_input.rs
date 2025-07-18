// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIngestionDestinationInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub app_bundle_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub ingestion_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about how ingested data is processed.</p>
    pub processing_configuration: ::std::option::Option<crate::types::ProcessingConfiguration>,
    /// <p>Contains information about the destination of ingested data.</p>
    pub destination_configuration: ::std::option::Option<crate::types::DestinationConfiguration>,
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateIngestionDestinationInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn app_bundle_identifier(&self) -> ::std::option::Option<&str> {
        self.app_bundle_identifier.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub fn ingestion_identifier(&self) -> ::std::option::Option<&str> {
        self.ingestion_identifier.as_deref()
    }
    /// <p>Contains information about how ingested data is processed.</p>
    pub fn processing_configuration(&self) -> ::std::option::Option<&crate::types::ProcessingConfiguration> {
        self.processing_configuration.as_ref()
    }
    /// <p>Contains information about the destination of ingested data.</p>
    pub fn destination_configuration(&self) -> ::std::option::Option<&crate::types::DestinationConfiguration> {
        self.destination_configuration.as_ref()
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateIngestionDestinationInput {
    /// Creates a new builder-style object to manufacture [`CreateIngestionDestinationInput`](crate::operation::create_ingestion_destination::CreateIngestionDestinationInput).
    pub fn builder() -> crate::operation::create_ingestion_destination::builders::CreateIngestionDestinationInputBuilder {
        crate::operation::create_ingestion_destination::builders::CreateIngestionDestinationInputBuilder::default()
    }
}

/// A builder for [`CreateIngestionDestinationInput`](crate::operation::create_ingestion_destination::CreateIngestionDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIngestionDestinationInputBuilder {
    pub(crate) app_bundle_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) ingestion_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) processing_configuration: ::std::option::Option<crate::types::ProcessingConfiguration>,
    pub(crate) destination_configuration: ::std::option::Option<crate::types::DestinationConfiguration>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateIngestionDestinationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    /// This field is required.
    pub fn app_bundle_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_bundle_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn set_app_bundle_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_bundle_identifier = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn get_app_bundle_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_bundle_identifier
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    /// This field is required.
    pub fn ingestion_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ingestion_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub fn set_ingestion_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ingestion_identifier = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub fn get_ingestion_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.ingestion_identifier
    }
    /// <p>Contains information about how ingested data is processed.</p>
    /// This field is required.
    pub fn processing_configuration(mut self, input: crate::types::ProcessingConfiguration) -> Self {
        self.processing_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about how ingested data is processed.</p>
    pub fn set_processing_configuration(mut self, input: ::std::option::Option<crate::types::ProcessingConfiguration>) -> Self {
        self.processing_configuration = input;
        self
    }
    /// <p>Contains information about how ingested data is processed.</p>
    pub fn get_processing_configuration(&self) -> &::std::option::Option<crate::types::ProcessingConfiguration> {
        &self.processing_configuration
    }
    /// <p>Contains information about the destination of ingested data.</p>
    /// This field is required.
    pub fn destination_configuration(mut self, input: crate::types::DestinationConfiguration) -> Self {
        self.destination_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the destination of ingested data.</p>
    pub fn set_destination_configuration(mut self, input: ::std::option::Option<crate::types::DestinationConfiguration>) -> Self {
        self.destination_configuration = input;
        self
    }
    /// <p>Contains information about the destination of ingested data.</p>
    pub fn get_destination_configuration(&self) -> &::std::option::Option<crate::types::DestinationConfiguration> {
        &self.destination_configuration
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateIngestionDestinationInput`](crate::operation::create_ingestion_destination::CreateIngestionDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_ingestion_destination::CreateIngestionDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_ingestion_destination::CreateIngestionDestinationInput {
            app_bundle_identifier: self.app_bundle_identifier,
            ingestion_identifier: self.ingestion_identifier,
            processing_configuration: self.processing_configuration,
            destination_configuration: self.destination_configuration,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
