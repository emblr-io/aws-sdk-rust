// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutPackageOriginConfigurationOutput {
    /// <p>A <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginConfiguration.html">PackageOriginConfiguration</a> object that describes the origin configuration set for the package. It contains a <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginRestrictions.html">PackageOriginRestrictions</a> object that describes how new versions of the package can be introduced to the repository.</p>
    pub origin_configuration: ::std::option::Option<crate::types::PackageOriginConfiguration>,
    _request_id: Option<String>,
}
impl PutPackageOriginConfigurationOutput {
    /// <p>A <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginConfiguration.html">PackageOriginConfiguration</a> object that describes the origin configuration set for the package. It contains a <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginRestrictions.html">PackageOriginRestrictions</a> object that describes how new versions of the package can be introduced to the repository.</p>
    pub fn origin_configuration(&self) -> ::std::option::Option<&crate::types::PackageOriginConfiguration> {
        self.origin_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutPackageOriginConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutPackageOriginConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutPackageOriginConfigurationOutput`](crate::operation::put_package_origin_configuration::PutPackageOriginConfigurationOutput).
    pub fn builder() -> crate::operation::put_package_origin_configuration::builders::PutPackageOriginConfigurationOutputBuilder {
        crate::operation::put_package_origin_configuration::builders::PutPackageOriginConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutPackageOriginConfigurationOutput`](crate::operation::put_package_origin_configuration::PutPackageOriginConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutPackageOriginConfigurationOutputBuilder {
    pub(crate) origin_configuration: ::std::option::Option<crate::types::PackageOriginConfiguration>,
    _request_id: Option<String>,
}
impl PutPackageOriginConfigurationOutputBuilder {
    /// <p>A <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginConfiguration.html">PackageOriginConfiguration</a> object that describes the origin configuration set for the package. It contains a <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginRestrictions.html">PackageOriginRestrictions</a> object that describes how new versions of the package can be introduced to the repository.</p>
    pub fn origin_configuration(mut self, input: crate::types::PackageOriginConfiguration) -> Self {
        self.origin_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginConfiguration.html">PackageOriginConfiguration</a> object that describes the origin configuration set for the package. It contains a <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginRestrictions.html">PackageOriginRestrictions</a> object that describes how new versions of the package can be introduced to the repository.</p>
    pub fn set_origin_configuration(mut self, input: ::std::option::Option<crate::types::PackageOriginConfiguration>) -> Self {
        self.origin_configuration = input;
        self
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginConfiguration.html">PackageOriginConfiguration</a> object that describes the origin configuration set for the package. It contains a <a href="https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageOriginRestrictions.html">PackageOriginRestrictions</a> object that describes how new versions of the package can be introduced to the repository.</p>
    pub fn get_origin_configuration(&self) -> &::std::option::Option<crate::types::PackageOriginConfiguration> {
        &self.origin_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutPackageOriginConfigurationOutput`](crate::operation::put_package_origin_configuration::PutPackageOriginConfigurationOutput).
    pub fn build(self) -> crate::operation::put_package_origin_configuration::PutPackageOriginConfigurationOutput {
        crate::operation::put_package_origin_configuration::PutPackageOriginConfigurationOutput {
            origin_configuration: self.origin_configuration,
            _request_id: self._request_id,
        }
    }
}
