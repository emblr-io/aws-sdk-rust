// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the response returned by the <code>CreatePackage</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePackageOutput {
    /// <p>Basic information about an OpenSearch Service package.</p>
    pub package_details: ::std::option::Option<crate::types::PackageDetails>,
    _request_id: Option<String>,
}
impl CreatePackageOutput {
    /// <p>Basic information about an OpenSearch Service package.</p>
    pub fn package_details(&self) -> ::std::option::Option<&crate::types::PackageDetails> {
        self.package_details.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePackageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePackageOutput {
    /// Creates a new builder-style object to manufacture [`CreatePackageOutput`](crate::operation::create_package::CreatePackageOutput).
    pub fn builder() -> crate::operation::create_package::builders::CreatePackageOutputBuilder {
        crate::operation::create_package::builders::CreatePackageOutputBuilder::default()
    }
}

/// A builder for [`CreatePackageOutput`](crate::operation::create_package::CreatePackageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePackageOutputBuilder {
    pub(crate) package_details: ::std::option::Option<crate::types::PackageDetails>,
    _request_id: Option<String>,
}
impl CreatePackageOutputBuilder {
    /// <p>Basic information about an OpenSearch Service package.</p>
    pub fn package_details(mut self, input: crate::types::PackageDetails) -> Self {
        self.package_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Basic information about an OpenSearch Service package.</p>
    pub fn set_package_details(mut self, input: ::std::option::Option<crate::types::PackageDetails>) -> Self {
        self.package_details = input;
        self
    }
    /// <p>Basic information about an OpenSearch Service package.</p>
    pub fn get_package_details(&self) -> &::std::option::Option<crate::types::PackageDetails> {
        &self.package_details
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePackageOutput`](crate::operation::create_package::CreatePackageOutput).
    pub fn build(self) -> crate::operation::create_package::CreatePackageOutput {
        crate::operation::create_package::CreatePackageOutput {
            package_details: self.package_details,
            _request_id: self._request_id,
        }
    }
}
