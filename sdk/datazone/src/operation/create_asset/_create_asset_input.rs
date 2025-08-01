// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateAssetInput {
    /// <p>Asset name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Amazon DataZone domain where the asset is created.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The external identifier of the asset.</p>
    pub external_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of this asset's type.</p>
    pub type_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The revision of this asset's type.</p>
    pub type_revision: ::std::option::Option<::std::string::String>,
    /// <p>Asset description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Glossary terms attached to the asset.</p>
    pub glossary_terms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Metadata forms attached to the asset.</p>
    pub forms_input: ::std::option::Option<::std::vec::Vec<crate::types::FormInput>>,
    /// <p>The unique identifier of the project that owns this asset.</p>
    pub owning_project_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The configuration of the automatically generated business-friendly metadata for the asset.</p>
    pub prediction_configuration: ::std::option::Option<crate::types::PredictionConfiguration>,
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateAssetInput {
    /// <p>Asset name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Amazon DataZone domain where the asset is created.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The external identifier of the asset.</p>
    pub fn external_identifier(&self) -> ::std::option::Option<&str> {
        self.external_identifier.as_deref()
    }
    /// <p>The unique identifier of this asset's type.</p>
    pub fn type_identifier(&self) -> ::std::option::Option<&str> {
        self.type_identifier.as_deref()
    }
    /// <p>The revision of this asset's type.</p>
    pub fn type_revision(&self) -> ::std::option::Option<&str> {
        self.type_revision.as_deref()
    }
    /// <p>Asset description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Glossary terms attached to the asset.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.glossary_terms.is_none()`.
    pub fn glossary_terms(&self) -> &[::std::string::String] {
        self.glossary_terms.as_deref().unwrap_or_default()
    }
    /// <p>Metadata forms attached to the asset.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.forms_input.is_none()`.
    pub fn forms_input(&self) -> &[crate::types::FormInput] {
        self.forms_input.as_deref().unwrap_or_default()
    }
    /// <p>The unique identifier of the project that owns this asset.</p>
    pub fn owning_project_identifier(&self) -> ::std::option::Option<&str> {
        self.owning_project_identifier.as_deref()
    }
    /// <p>The configuration of the automatically generated business-friendly metadata for the asset.</p>
    pub fn prediction_configuration(&self) -> ::std::option::Option<&crate::types::PredictionConfiguration> {
        self.prediction_configuration.as_ref()
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateAssetInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAssetInput");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("external_identifier", &self.external_identifier);
        formatter.field("type_identifier", &self.type_identifier);
        formatter.field("type_revision", &self.type_revision);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("glossary_terms", &self.glossary_terms);
        formatter.field("forms_input", &"*** Sensitive Data Redacted ***");
        formatter.field("owning_project_identifier", &self.owning_project_identifier);
        formatter.field("prediction_configuration", &self.prediction_configuration);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
impl CreateAssetInput {
    /// Creates a new builder-style object to manufacture [`CreateAssetInput`](crate::operation::create_asset::CreateAssetInput).
    pub fn builder() -> crate::operation::create_asset::builders::CreateAssetInputBuilder {
        crate::operation::create_asset::builders::CreateAssetInputBuilder::default()
    }
}

/// A builder for [`CreateAssetInput`](crate::operation::create_asset::CreateAssetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateAssetInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) external_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) type_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) type_revision: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) glossary_terms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) forms_input: ::std::option::Option<::std::vec::Vec<crate::types::FormInput>>,
    pub(crate) owning_project_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) prediction_configuration: ::std::option::Option<crate::types::PredictionConfiguration>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateAssetInputBuilder {
    /// <p>Asset name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Asset name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Asset name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Amazon DataZone domain where the asset is created.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon DataZone domain where the asset is created.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>Amazon DataZone domain where the asset is created.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The external identifier of the asset.</p>
    pub fn external_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The external identifier of the asset.</p>
    pub fn set_external_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_identifier = input;
        self
    }
    /// <p>The external identifier of the asset.</p>
    pub fn get_external_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_identifier
    }
    /// <p>The unique identifier of this asset's type.</p>
    /// This field is required.
    pub fn type_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of this asset's type.</p>
    pub fn set_type_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_identifier = input;
        self
    }
    /// <p>The unique identifier of this asset's type.</p>
    pub fn get_type_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_identifier
    }
    /// <p>The revision of this asset's type.</p>
    pub fn type_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision of this asset's type.</p>
    pub fn set_type_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_revision = input;
        self
    }
    /// <p>The revision of this asset's type.</p>
    pub fn get_type_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_revision
    }
    /// <p>Asset description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Asset description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Asset description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `glossary_terms`.
    ///
    /// To override the contents of this collection use [`set_glossary_terms`](Self::set_glossary_terms).
    ///
    /// <p>Glossary terms attached to the asset.</p>
    pub fn glossary_terms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.glossary_terms.unwrap_or_default();
        v.push(input.into());
        self.glossary_terms = ::std::option::Option::Some(v);
        self
    }
    /// <p>Glossary terms attached to the asset.</p>
    pub fn set_glossary_terms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.glossary_terms = input;
        self
    }
    /// <p>Glossary terms attached to the asset.</p>
    pub fn get_glossary_terms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.glossary_terms
    }
    /// Appends an item to `forms_input`.
    ///
    /// To override the contents of this collection use [`set_forms_input`](Self::set_forms_input).
    ///
    /// <p>Metadata forms attached to the asset.</p>
    pub fn forms_input(mut self, input: crate::types::FormInput) -> Self {
        let mut v = self.forms_input.unwrap_or_default();
        v.push(input);
        self.forms_input = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata forms attached to the asset.</p>
    pub fn set_forms_input(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FormInput>>) -> Self {
        self.forms_input = input;
        self
    }
    /// <p>Metadata forms attached to the asset.</p>
    pub fn get_forms_input(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FormInput>> {
        &self.forms_input
    }
    /// <p>The unique identifier of the project that owns this asset.</p>
    /// This field is required.
    pub fn owning_project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owning_project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the project that owns this asset.</p>
    pub fn set_owning_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owning_project_identifier = input;
        self
    }
    /// <p>The unique identifier of the project that owns this asset.</p>
    pub fn get_owning_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.owning_project_identifier
    }
    /// <p>The configuration of the automatically generated business-friendly metadata for the asset.</p>
    pub fn prediction_configuration(mut self, input: crate::types::PredictionConfiguration) -> Self {
        self.prediction_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration of the automatically generated business-friendly metadata for the asset.</p>
    pub fn set_prediction_configuration(mut self, input: ::std::option::Option<crate::types::PredictionConfiguration>) -> Self {
        self.prediction_configuration = input;
        self
    }
    /// <p>The configuration of the automatically generated business-friendly metadata for the asset.</p>
    pub fn get_prediction_configuration(&self) -> &::std::option::Option<crate::types::PredictionConfiguration> {
        &self.prediction_configuration
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateAssetInput`](crate::operation::create_asset::CreateAssetInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_asset::CreateAssetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_asset::CreateAssetInput {
            name: self.name,
            domain_identifier: self.domain_identifier,
            external_identifier: self.external_identifier,
            type_identifier: self.type_identifier,
            type_revision: self.type_revision,
            description: self.description,
            glossary_terms: self.glossary_terms,
            forms_input: self.forms_input,
            owning_project_identifier: self.owning_project_identifier,
            prediction_configuration: self.prediction_configuration,
            client_token: self.client_token,
        })
    }
}
impl ::std::fmt::Debug for CreateAssetInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAssetInputBuilder");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("external_identifier", &self.external_identifier);
        formatter.field("type_identifier", &self.type_identifier);
        formatter.field("type_revision", &self.type_revision);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("glossary_terms", &self.glossary_terms);
        formatter.field("forms_input", &"*** Sensitive Data Redacted ***");
        formatter.field("owning_project_identifier", &self.owning_project_identifier);
        formatter.field("prediction_configuration", &self.prediction_configuration);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
