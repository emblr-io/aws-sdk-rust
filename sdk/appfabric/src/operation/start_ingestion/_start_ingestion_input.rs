// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartIngestionInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub ingestion_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub app_bundle_identifier: ::std::option::Option<::std::string::String>,
}
impl StartIngestionInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the ingestion to use for the request.</p>
    pub fn ingestion_identifier(&self) -> ::std::option::Option<&str> {
        self.ingestion_identifier.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn app_bundle_identifier(&self) -> ::std::option::Option<&str> {
        self.app_bundle_identifier.as_deref()
    }
}
impl StartIngestionInput {
    /// Creates a new builder-style object to manufacture [`StartIngestionInput`](crate::operation::start_ingestion::StartIngestionInput).
    pub fn builder() -> crate::operation::start_ingestion::builders::StartIngestionInputBuilder {
        crate::operation::start_ingestion::builders::StartIngestionInputBuilder::default()
    }
}

/// A builder for [`StartIngestionInput`](crate::operation::start_ingestion::StartIngestionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartIngestionInputBuilder {
    pub(crate) ingestion_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) app_bundle_identifier: ::std::option::Option<::std::string::String>,
}
impl StartIngestionInputBuilder {
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
    /// Consumes the builder and constructs a [`StartIngestionInput`](crate::operation::start_ingestion::StartIngestionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_ingestion::StartIngestionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_ingestion::StartIngestionInput {
            ingestion_identifier: self.ingestion_identifier,
            app_bundle_identifier: self.app_bundle_identifier,
        })
    }
}
