// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartMetadataGenerationRunInput {
    /// <p>The ID of the Amazon DataZone domain where you want to start a metadata generation run.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of the metadata generation run.</p>
    pub r#type: ::std::option::Option<crate::types::MetadataGenerationRunType>,
    /// <p>The asset for which you want to start a metadata generation run.</p>
    pub target: ::std::option::Option<crate::types::MetadataGenerationRunTarget>,
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the project that owns the asset for which you want to start a metadata generation run.</p>
    pub owning_project_identifier: ::std::option::Option<::std::string::String>,
}
impl StartMetadataGenerationRunInput {
    /// <p>The ID of the Amazon DataZone domain where you want to start a metadata generation run.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The type of the metadata generation run.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::MetadataGenerationRunType> {
        self.r#type.as_ref()
    }
    /// <p>The asset for which you want to start a metadata generation run.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::MetadataGenerationRunTarget> {
        self.target.as_ref()
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The ID of the project that owns the asset for which you want to start a metadata generation run.</p>
    pub fn owning_project_identifier(&self) -> ::std::option::Option<&str> {
        self.owning_project_identifier.as_deref()
    }
}
impl StartMetadataGenerationRunInput {
    /// Creates a new builder-style object to manufacture [`StartMetadataGenerationRunInput`](crate::operation::start_metadata_generation_run::StartMetadataGenerationRunInput).
    pub fn builder() -> crate::operation::start_metadata_generation_run::builders::StartMetadataGenerationRunInputBuilder {
        crate::operation::start_metadata_generation_run::builders::StartMetadataGenerationRunInputBuilder::default()
    }
}

/// A builder for [`StartMetadataGenerationRunInput`](crate::operation::start_metadata_generation_run::StartMetadataGenerationRunInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartMetadataGenerationRunInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::MetadataGenerationRunType>,
    pub(crate) target: ::std::option::Option<crate::types::MetadataGenerationRunTarget>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) owning_project_identifier: ::std::option::Option<::std::string::String>,
}
impl StartMetadataGenerationRunInputBuilder {
    /// <p>The ID of the Amazon DataZone domain where you want to start a metadata generation run.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain where you want to start a metadata generation run.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain where you want to start a metadata generation run.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The type of the metadata generation run.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::MetadataGenerationRunType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the metadata generation run.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::MetadataGenerationRunType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the metadata generation run.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::MetadataGenerationRunType> {
        &self.r#type
    }
    /// <p>The asset for which you want to start a metadata generation run.</p>
    /// This field is required.
    pub fn target(mut self, input: crate::types::MetadataGenerationRunTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The asset for which you want to start a metadata generation run.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::MetadataGenerationRunTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>The asset for which you want to start a metadata generation run.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::MetadataGenerationRunTarget> {
        &self.target
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request. This field is automatically populated if not provided.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The ID of the project that owns the asset for which you want to start a metadata generation run.</p>
    /// This field is required.
    pub fn owning_project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owning_project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the project that owns the asset for which you want to start a metadata generation run.</p>
    pub fn set_owning_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owning_project_identifier = input;
        self
    }
    /// <p>The ID of the project that owns the asset for which you want to start a metadata generation run.</p>
    pub fn get_owning_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.owning_project_identifier
    }
    /// Consumes the builder and constructs a [`StartMetadataGenerationRunInput`](crate::operation::start_metadata_generation_run::StartMetadataGenerationRunInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_metadata_generation_run::StartMetadataGenerationRunInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_metadata_generation_run::StartMetadataGenerationRunInput {
            domain_identifier: self.domain_identifier,
            r#type: self.r#type,
            target: self.target,
            client_token: self.client_token,
            owning_project_identifier: self.owning_project_identifier,
        })
    }
}
