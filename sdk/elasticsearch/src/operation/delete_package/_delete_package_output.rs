// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for response parameters to <code> <code>DeletePackage</code> </code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePackageOutput {
    /// <p><code>PackageDetails</code></p>
    pub package_details: ::std::option::Option<crate::types::PackageDetails>,
    _request_id: Option<String>,
}
impl DeletePackageOutput {
    /// <p><code>PackageDetails</code></p>
    pub fn package_details(&self) -> ::std::option::Option<&crate::types::PackageDetails> {
        self.package_details.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeletePackageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeletePackageOutput {
    /// Creates a new builder-style object to manufacture [`DeletePackageOutput`](crate::operation::delete_package::DeletePackageOutput).
    pub fn builder() -> crate::operation::delete_package::builders::DeletePackageOutputBuilder {
        crate::operation::delete_package::builders::DeletePackageOutputBuilder::default()
    }
}

/// A builder for [`DeletePackageOutput`](crate::operation::delete_package::DeletePackageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePackageOutputBuilder {
    pub(crate) package_details: ::std::option::Option<crate::types::PackageDetails>,
    _request_id: Option<String>,
}
impl DeletePackageOutputBuilder {
    /// <p><code>PackageDetails</code></p>
    pub fn package_details(mut self, input: crate::types::PackageDetails) -> Self {
        self.package_details = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>PackageDetails</code></p>
    pub fn set_package_details(mut self, input: ::std::option::Option<crate::types::PackageDetails>) -> Self {
        self.package_details = input;
        self
    }
    /// <p><code>PackageDetails</code></p>
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
    /// Consumes the builder and constructs a [`DeletePackageOutput`](crate::operation::delete_package::DeletePackageOutput).
    pub fn build(self) -> crate::operation::delete_package::DeletePackageOutput {
        crate::operation::delete_package::DeletePackageOutput {
            package_details: self.package_details,
            _request_id: self._request_id,
        }
    }
}
