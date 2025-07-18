// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The resource config for the data model, configured as a part of the Amplify project.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BackendApiResourceConfig {
    /// <p>Additional authentication methods used to interact with your data models.</p>
    pub additional_auth_types: ::std::option::Option<::std::vec::Vec<crate::types::BackendApiAuthType>>,
    /// <p>The API name used to interact with the data model, configured as a part of your Amplify project.</p>
    pub api_name: ::std::option::Option<::std::string::String>,
    /// <p>The conflict resolution strategy for your data stored in the data models.</p>
    pub conflict_resolution: ::std::option::Option<crate::types::BackendApiConflictResolution>,
    /// <p>The default authentication type for interacting with the configured data models in your Amplify project.</p>
    pub default_auth_type: ::std::option::Option<crate::types::BackendApiAuthType>,
    /// <p>The service used to provision and interact with the data model.</p>
    pub service: ::std::option::Option<::std::string::String>,
    /// <p>The definition of the data model in the annotated transform of the GraphQL schema.</p>
    pub transform_schema: ::std::option::Option<::std::string::String>,
}
impl BackendApiResourceConfig {
    /// <p>Additional authentication methods used to interact with your data models.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_auth_types.is_none()`.
    pub fn additional_auth_types(&self) -> &[crate::types::BackendApiAuthType] {
        self.additional_auth_types.as_deref().unwrap_or_default()
    }
    /// <p>The API name used to interact with the data model, configured as a part of your Amplify project.</p>
    pub fn api_name(&self) -> ::std::option::Option<&str> {
        self.api_name.as_deref()
    }
    /// <p>The conflict resolution strategy for your data stored in the data models.</p>
    pub fn conflict_resolution(&self) -> ::std::option::Option<&crate::types::BackendApiConflictResolution> {
        self.conflict_resolution.as_ref()
    }
    /// <p>The default authentication type for interacting with the configured data models in your Amplify project.</p>
    pub fn default_auth_type(&self) -> ::std::option::Option<&crate::types::BackendApiAuthType> {
        self.default_auth_type.as_ref()
    }
    /// <p>The service used to provision and interact with the data model.</p>
    pub fn service(&self) -> ::std::option::Option<&str> {
        self.service.as_deref()
    }
    /// <p>The definition of the data model in the annotated transform of the GraphQL schema.</p>
    pub fn transform_schema(&self) -> ::std::option::Option<&str> {
        self.transform_schema.as_deref()
    }
}
impl BackendApiResourceConfig {
    /// Creates a new builder-style object to manufacture [`BackendApiResourceConfig`](crate::types::BackendApiResourceConfig).
    pub fn builder() -> crate::types::builders::BackendApiResourceConfigBuilder {
        crate::types::builders::BackendApiResourceConfigBuilder::default()
    }
}

/// A builder for [`BackendApiResourceConfig`](crate::types::BackendApiResourceConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BackendApiResourceConfigBuilder {
    pub(crate) additional_auth_types: ::std::option::Option<::std::vec::Vec<crate::types::BackendApiAuthType>>,
    pub(crate) api_name: ::std::option::Option<::std::string::String>,
    pub(crate) conflict_resolution: ::std::option::Option<crate::types::BackendApiConflictResolution>,
    pub(crate) default_auth_type: ::std::option::Option<crate::types::BackendApiAuthType>,
    pub(crate) service: ::std::option::Option<::std::string::String>,
    pub(crate) transform_schema: ::std::option::Option<::std::string::String>,
}
impl BackendApiResourceConfigBuilder {
    /// Appends an item to `additional_auth_types`.
    ///
    /// To override the contents of this collection use [`set_additional_auth_types`](Self::set_additional_auth_types).
    ///
    /// <p>Additional authentication methods used to interact with your data models.</p>
    pub fn additional_auth_types(mut self, input: crate::types::BackendApiAuthType) -> Self {
        let mut v = self.additional_auth_types.unwrap_or_default();
        v.push(input);
        self.additional_auth_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Additional authentication methods used to interact with your data models.</p>
    pub fn set_additional_auth_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BackendApiAuthType>>) -> Self {
        self.additional_auth_types = input;
        self
    }
    /// <p>Additional authentication methods used to interact with your data models.</p>
    pub fn get_additional_auth_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BackendApiAuthType>> {
        &self.additional_auth_types
    }
    /// <p>The API name used to interact with the data model, configured as a part of your Amplify project.</p>
    pub fn api_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API name used to interact with the data model, configured as a part of your Amplify project.</p>
    pub fn set_api_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_name = input;
        self
    }
    /// <p>The API name used to interact with the data model, configured as a part of your Amplify project.</p>
    pub fn get_api_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_name
    }
    /// <p>The conflict resolution strategy for your data stored in the data models.</p>
    pub fn conflict_resolution(mut self, input: crate::types::BackendApiConflictResolution) -> Self {
        self.conflict_resolution = ::std::option::Option::Some(input);
        self
    }
    /// <p>The conflict resolution strategy for your data stored in the data models.</p>
    pub fn set_conflict_resolution(mut self, input: ::std::option::Option<crate::types::BackendApiConflictResolution>) -> Self {
        self.conflict_resolution = input;
        self
    }
    /// <p>The conflict resolution strategy for your data stored in the data models.</p>
    pub fn get_conflict_resolution(&self) -> &::std::option::Option<crate::types::BackendApiConflictResolution> {
        &self.conflict_resolution
    }
    /// <p>The default authentication type for interacting with the configured data models in your Amplify project.</p>
    pub fn default_auth_type(mut self, input: crate::types::BackendApiAuthType) -> Self {
        self.default_auth_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default authentication type for interacting with the configured data models in your Amplify project.</p>
    pub fn set_default_auth_type(mut self, input: ::std::option::Option<crate::types::BackendApiAuthType>) -> Self {
        self.default_auth_type = input;
        self
    }
    /// <p>The default authentication type for interacting with the configured data models in your Amplify project.</p>
    pub fn get_default_auth_type(&self) -> &::std::option::Option<crate::types::BackendApiAuthType> {
        &self.default_auth_type
    }
    /// <p>The service used to provision and interact with the data model.</p>
    pub fn service(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service used to provision and interact with the data model.</p>
    pub fn set_service(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service = input;
        self
    }
    /// <p>The service used to provision and interact with the data model.</p>
    pub fn get_service(&self) -> &::std::option::Option<::std::string::String> {
        &self.service
    }
    /// <p>The definition of the data model in the annotated transform of the GraphQL schema.</p>
    pub fn transform_schema(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transform_schema = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The definition of the data model in the annotated transform of the GraphQL schema.</p>
    pub fn set_transform_schema(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transform_schema = input;
        self
    }
    /// <p>The definition of the data model in the annotated transform of the GraphQL schema.</p>
    pub fn get_transform_schema(&self) -> &::std::option::Option<::std::string::String> {
        &self.transform_schema
    }
    /// Consumes the builder and constructs a [`BackendApiResourceConfig`](crate::types::BackendApiResourceConfig).
    pub fn build(self) -> crate::types::BackendApiResourceConfig {
        crate::types::BackendApiResourceConfig {
            additional_auth_types: self.additional_auth_types,
            api_name: self.api_name,
            conflict_resolution: self.conflict_resolution,
            default_auth_type: self.default_auth_type,
            service: self.service,
            transform_schema: self.transform_schema,
        }
    }
}
