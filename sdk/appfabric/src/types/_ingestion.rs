// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about an ingestion.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ingestion {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the app bundle for the ingestion.</p>
    pub app_bundle_arn: ::std::string::String,
    /// <p>The name of the application.</p>
    pub app: ::std::string::String,
    /// <p>The ID of the application tenant.</p>
    pub tenant_id: ::std::string::String,
    /// <p>The timestamp of when the ingestion was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The timestamp of when the ingestion was last updated.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
    /// <p>The status of the ingestion.</p>
    pub state: crate::types::IngestionState,
    /// <p>The type of the ingestion.</p>
    pub ingestion_type: crate::types::IngestionType,
}
impl Ingestion {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the app bundle for the ingestion.</p>
    pub fn app_bundle_arn(&self) -> &str {
        use std::ops::Deref;
        self.app_bundle_arn.deref()
    }
    /// <p>The name of the application.</p>
    pub fn app(&self) -> &str {
        use std::ops::Deref;
        self.app.deref()
    }
    /// <p>The ID of the application tenant.</p>
    pub fn tenant_id(&self) -> &str {
        use std::ops::Deref;
        self.tenant_id.deref()
    }
    /// <p>The timestamp of when the ingestion was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The timestamp of when the ingestion was last updated.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
    /// <p>The status of the ingestion.</p>
    pub fn state(&self) -> &crate::types::IngestionState {
        &self.state
    }
    /// <p>The type of the ingestion.</p>
    pub fn ingestion_type(&self) -> &crate::types::IngestionType {
        &self.ingestion_type
    }
}
impl Ingestion {
    /// Creates a new builder-style object to manufacture [`Ingestion`](crate::types::Ingestion).
    pub fn builder() -> crate::types::builders::IngestionBuilder {
        crate::types::builders::IngestionBuilder::default()
    }
}

/// A builder for [`Ingestion`](crate::types::Ingestion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IngestionBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) app_bundle_arn: ::std::option::Option<::std::string::String>,
    pub(crate) app: ::std::option::Option<::std::string::String>,
    pub(crate) tenant_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) state: ::std::option::Option<crate::types::IngestionState>,
    pub(crate) ingestion_type: ::std::option::Option<crate::types::IngestionType>,
}
impl IngestionBuilder {
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the ingestion.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The Amazon Resource Name (ARN) of the app bundle for the ingestion.</p>
    /// This field is required.
    pub fn app_bundle_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_bundle_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the app bundle for the ingestion.</p>
    pub fn set_app_bundle_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_bundle_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the app bundle for the ingestion.</p>
    pub fn get_app_bundle_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_bundle_arn
    }
    /// <p>The name of the application.</p>
    /// This field is required.
    pub fn app(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application.</p>
    pub fn set_app(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app = input;
        self
    }
    /// <p>The name of the application.</p>
    pub fn get_app(&self) -> &::std::option::Option<::std::string::String> {
        &self.app
    }
    /// <p>The ID of the application tenant.</p>
    /// This field is required.
    pub fn tenant_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tenant_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application tenant.</p>
    pub fn set_tenant_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tenant_id = input;
        self
    }
    /// <p>The ID of the application tenant.</p>
    pub fn get_tenant_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.tenant_id
    }
    /// <p>The timestamp of when the ingestion was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the ingestion was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the ingestion was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp of when the ingestion was last updated.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the ingestion was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp of when the ingestion was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The status of the ingestion.</p>
    /// This field is required.
    pub fn state(mut self, input: crate::types::IngestionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the ingestion.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::IngestionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The status of the ingestion.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::IngestionState> {
        &self.state
    }
    /// <p>The type of the ingestion.</p>
    /// This field is required.
    pub fn ingestion_type(mut self, input: crate::types::IngestionType) -> Self {
        self.ingestion_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the ingestion.</p>
    pub fn set_ingestion_type(mut self, input: ::std::option::Option<crate::types::IngestionType>) -> Self {
        self.ingestion_type = input;
        self
    }
    /// <p>The type of the ingestion.</p>
    pub fn get_ingestion_type(&self) -> &::std::option::Option<crate::types::IngestionType> {
        &self.ingestion_type
    }
    /// Consumes the builder and constructs a [`Ingestion`](crate::types::Ingestion).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::IngestionBuilder::arn)
    /// - [`app_bundle_arn`](crate::types::builders::IngestionBuilder::app_bundle_arn)
    /// - [`app`](crate::types::builders::IngestionBuilder::app)
    /// - [`tenant_id`](crate::types::builders::IngestionBuilder::tenant_id)
    /// - [`created_at`](crate::types::builders::IngestionBuilder::created_at)
    /// - [`updated_at`](crate::types::builders::IngestionBuilder::updated_at)
    /// - [`state`](crate::types::builders::IngestionBuilder::state)
    /// - [`ingestion_type`](crate::types::builders::IngestionBuilder::ingestion_type)
    pub fn build(self) -> ::std::result::Result<crate::types::Ingestion, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Ingestion {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building Ingestion",
                )
            })?,
            app_bundle_arn: self.app_bundle_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_bundle_arn",
                    "app_bundle_arn was not specified but it is required when building Ingestion",
                )
            })?,
            app: self.app.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app",
                    "app was not specified but it is required when building Ingestion",
                )
            })?,
            tenant_id: self.tenant_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tenant_id",
                    "tenant_id was not specified but it is required when building Ingestion",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building Ingestion",
                )
            })?,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building Ingestion",
                )
            })?,
            state: self.state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "state",
                    "state was not specified but it is required when building Ingestion",
                )
            })?,
            ingestion_type: self.ingestion_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ingestion_type",
                    "ingestion_type was not specified but it is required when building Ingestion",
                )
            })?,
        })
    }
}
