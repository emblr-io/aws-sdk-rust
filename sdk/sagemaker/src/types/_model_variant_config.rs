// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the deployment options of a model.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelVariantConfig {
    /// <p>The name of the Amazon SageMaker Model entity.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the variant.</p>
    pub variant_name: ::std::option::Option<::std::string::String>,
    /// <p>The configuration for the infrastructure that the model will be deployed to.</p>
    pub infrastructure_config: ::std::option::Option<crate::types::ModelInfrastructureConfig>,
}
impl ModelVariantConfig {
    /// <p>The name of the Amazon SageMaker Model entity.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
    /// <p>The name of the variant.</p>
    pub fn variant_name(&self) -> ::std::option::Option<&str> {
        self.variant_name.as_deref()
    }
    /// <p>The configuration for the infrastructure that the model will be deployed to.</p>
    pub fn infrastructure_config(&self) -> ::std::option::Option<&crate::types::ModelInfrastructureConfig> {
        self.infrastructure_config.as_ref()
    }
}
impl ModelVariantConfig {
    /// Creates a new builder-style object to manufacture [`ModelVariantConfig`](crate::types::ModelVariantConfig).
    pub fn builder() -> crate::types::builders::ModelVariantConfigBuilder {
        crate::types::builders::ModelVariantConfigBuilder::default()
    }
}

/// A builder for [`ModelVariantConfig`](crate::types::ModelVariantConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelVariantConfigBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
    pub(crate) variant_name: ::std::option::Option<::std::string::String>,
    pub(crate) infrastructure_config: ::std::option::Option<crate::types::ModelInfrastructureConfig>,
}
impl ModelVariantConfigBuilder {
    /// <p>The name of the Amazon SageMaker Model entity.</p>
    /// This field is required.
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon SageMaker Model entity.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the Amazon SageMaker Model entity.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// <p>The name of the variant.</p>
    /// This field is required.
    pub fn variant_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.variant_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the variant.</p>
    pub fn set_variant_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.variant_name = input;
        self
    }
    /// <p>The name of the variant.</p>
    pub fn get_variant_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.variant_name
    }
    /// <p>The configuration for the infrastructure that the model will be deployed to.</p>
    /// This field is required.
    pub fn infrastructure_config(mut self, input: crate::types::ModelInfrastructureConfig) -> Self {
        self.infrastructure_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the infrastructure that the model will be deployed to.</p>
    pub fn set_infrastructure_config(mut self, input: ::std::option::Option<crate::types::ModelInfrastructureConfig>) -> Self {
        self.infrastructure_config = input;
        self
    }
    /// <p>The configuration for the infrastructure that the model will be deployed to.</p>
    pub fn get_infrastructure_config(&self) -> &::std::option::Option<crate::types::ModelInfrastructureConfig> {
        &self.infrastructure_config
    }
    /// Consumes the builder and constructs a [`ModelVariantConfig`](crate::types::ModelVariantConfig).
    pub fn build(self) -> crate::types::ModelVariantConfig {
        crate::types::ModelVariantConfig {
            model_name: self.model_name,
            variant_name: self.variant_name,
            infrastructure_config: self.infrastructure_config,
        }
    }
}
