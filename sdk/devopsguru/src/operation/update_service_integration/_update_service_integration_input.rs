// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServiceIntegrationInput {
    /// <p>An <code>IntegratedServiceConfig</code> object used to specify the integrated service you want to update, and whether you want to update it to enabled or disabled.</p>
    pub service_integration: ::std::option::Option<crate::types::UpdateServiceIntegrationConfig>,
}
impl UpdateServiceIntegrationInput {
    /// <p>An <code>IntegratedServiceConfig</code> object used to specify the integrated service you want to update, and whether you want to update it to enabled or disabled.</p>
    pub fn service_integration(&self) -> ::std::option::Option<&crate::types::UpdateServiceIntegrationConfig> {
        self.service_integration.as_ref()
    }
}
impl UpdateServiceIntegrationInput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceIntegrationInput`](crate::operation::update_service_integration::UpdateServiceIntegrationInput).
    pub fn builder() -> crate::operation::update_service_integration::builders::UpdateServiceIntegrationInputBuilder {
        crate::operation::update_service_integration::builders::UpdateServiceIntegrationInputBuilder::default()
    }
}

/// A builder for [`UpdateServiceIntegrationInput`](crate::operation::update_service_integration::UpdateServiceIntegrationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServiceIntegrationInputBuilder {
    pub(crate) service_integration: ::std::option::Option<crate::types::UpdateServiceIntegrationConfig>,
}
impl UpdateServiceIntegrationInputBuilder {
    /// <p>An <code>IntegratedServiceConfig</code> object used to specify the integrated service you want to update, and whether you want to update it to enabled or disabled.</p>
    /// This field is required.
    pub fn service_integration(mut self, input: crate::types::UpdateServiceIntegrationConfig) -> Self {
        self.service_integration = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <code>IntegratedServiceConfig</code> object used to specify the integrated service you want to update, and whether you want to update it to enabled or disabled.</p>
    pub fn set_service_integration(mut self, input: ::std::option::Option<crate::types::UpdateServiceIntegrationConfig>) -> Self {
        self.service_integration = input;
        self
    }
    /// <p>An <code>IntegratedServiceConfig</code> object used to specify the integrated service you want to update, and whether you want to update it to enabled or disabled.</p>
    pub fn get_service_integration(&self) -> &::std::option::Option<crate::types::UpdateServiceIntegrationConfig> {
        &self.service_integration
    }
    /// Consumes the builder and constructs a [`UpdateServiceIntegrationInput`](crate::operation::update_service_integration::UpdateServiceIntegrationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_service_integration::UpdateServiceIntegrationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_service_integration::UpdateServiceIntegrationInput {
            service_integration: self.service_integration,
        })
    }
}
