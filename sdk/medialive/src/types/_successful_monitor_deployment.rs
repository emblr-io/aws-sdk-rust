// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Represents the latest successful monitor deployment of a signal map.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SuccessfulMonitorDeployment {
    /// URI associated with a signal map's monitor deployment.
    pub details_uri: ::std::option::Option<::std::string::String>,
    /// A signal map's monitor deployment status.
    pub status: ::std::option::Option<crate::types::SignalMapMonitorDeploymentStatus>,
}
impl SuccessfulMonitorDeployment {
    /// URI associated with a signal map's monitor deployment.
    pub fn details_uri(&self) -> ::std::option::Option<&str> {
        self.details_uri.as_deref()
    }
    /// A signal map's monitor deployment status.
    pub fn status(&self) -> ::std::option::Option<&crate::types::SignalMapMonitorDeploymentStatus> {
        self.status.as_ref()
    }
}
impl SuccessfulMonitorDeployment {
    /// Creates a new builder-style object to manufacture [`SuccessfulMonitorDeployment`](crate::types::SuccessfulMonitorDeployment).
    pub fn builder() -> crate::types::builders::SuccessfulMonitorDeploymentBuilder {
        crate::types::builders::SuccessfulMonitorDeploymentBuilder::default()
    }
}

/// A builder for [`SuccessfulMonitorDeployment`](crate::types::SuccessfulMonitorDeployment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SuccessfulMonitorDeploymentBuilder {
    pub(crate) details_uri: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::SignalMapMonitorDeploymentStatus>,
}
impl SuccessfulMonitorDeploymentBuilder {
    /// URI associated with a signal map's monitor deployment.
    /// This field is required.
    pub fn details_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// URI associated with a signal map's monitor deployment.
    pub fn set_details_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details_uri = input;
        self
    }
    /// URI associated with a signal map's monitor deployment.
    pub fn get_details_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.details_uri
    }
    /// A signal map's monitor deployment status.
    /// This field is required.
    pub fn status(mut self, input: crate::types::SignalMapMonitorDeploymentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// A signal map's monitor deployment status.
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SignalMapMonitorDeploymentStatus>) -> Self {
        self.status = input;
        self
    }
    /// A signal map's monitor deployment status.
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SignalMapMonitorDeploymentStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`SuccessfulMonitorDeployment`](crate::types::SuccessfulMonitorDeployment).
    pub fn build(self) -> crate::types::SuccessfulMonitorDeployment {
        crate::types::SuccessfulMonitorDeployment {
            details_uri: self.details_uri,
            status: self.status,
        }
    }
}
