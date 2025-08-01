// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// The endpoint URL used to access an Asset using one PackagingConfiguration.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EgressEndpoint {
    /// The ID of the PackagingConfiguration being applied to the Asset.
    pub packaging_configuration_id: ::std::option::Option<::std::string::String>,
    /// The current processing status of the asset used for the packaging configuration. The status can be either QUEUED, PROCESSING, PLAYABLE, or FAILED. Status information won't be available for most assets ingested before 2021-09-30.
    pub status: ::std::option::Option<::std::string::String>,
    /// The URL of the parent manifest for the repackaged Asset.
    pub url: ::std::option::Option<::std::string::String>,
}
impl EgressEndpoint {
    /// The ID of the PackagingConfiguration being applied to the Asset.
    pub fn packaging_configuration_id(&self) -> ::std::option::Option<&str> {
        self.packaging_configuration_id.as_deref()
    }
    /// The current processing status of the asset used for the packaging configuration. The status can be either QUEUED, PROCESSING, PLAYABLE, or FAILED. Status information won't be available for most assets ingested before 2021-09-30.
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// The URL of the parent manifest for the repackaged Asset.
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl EgressEndpoint {
    /// Creates a new builder-style object to manufacture [`EgressEndpoint`](crate::types::EgressEndpoint).
    pub fn builder() -> crate::types::builders::EgressEndpointBuilder {
        crate::types::builders::EgressEndpointBuilder::default()
    }
}

/// A builder for [`EgressEndpoint`](crate::types::EgressEndpoint).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EgressEndpointBuilder {
    pub(crate) packaging_configuration_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl EgressEndpointBuilder {
    /// The ID of the PackagingConfiguration being applied to the Asset.
    pub fn packaging_configuration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.packaging_configuration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the PackagingConfiguration being applied to the Asset.
    pub fn set_packaging_configuration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.packaging_configuration_id = input;
        self
    }
    /// The ID of the PackagingConfiguration being applied to the Asset.
    pub fn get_packaging_configuration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.packaging_configuration_id
    }
    /// The current processing status of the asset used for the packaging configuration. The status can be either QUEUED, PROCESSING, PLAYABLE, or FAILED. Status information won't be available for most assets ingested before 2021-09-30.
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// The current processing status of the asset used for the packaging configuration. The status can be either QUEUED, PROCESSING, PLAYABLE, or FAILED. Status information won't be available for most assets ingested before 2021-09-30.
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// The current processing status of the asset used for the packaging configuration. The status can be either QUEUED, PROCESSING, PLAYABLE, or FAILED. Status information won't be available for most assets ingested before 2021-09-30.
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// The URL of the parent manifest for the repackaged Asset.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// The URL of the parent manifest for the repackaged Asset.
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// The URL of the parent manifest for the repackaged Asset.
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`EgressEndpoint`](crate::types::EgressEndpoint).
    pub fn build(self) -> crate::types::EgressEndpoint {
        crate::types::EgressEndpoint {
            packaging_configuration_id: self.packaging_configuration_id,
            status: self.status,
            url: self.url,
        }
    }
}
