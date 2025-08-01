// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for response returned by <code> <code>DissociatePackage</code> </code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DissociatePackageOutput {
    /// <p><code>DomainPackageDetails</code></p>
    pub domain_package_details: ::std::option::Option<crate::types::DomainPackageDetails>,
    _request_id: Option<String>,
}
impl DissociatePackageOutput {
    /// <p><code>DomainPackageDetails</code></p>
    pub fn domain_package_details(&self) -> ::std::option::Option<&crate::types::DomainPackageDetails> {
        self.domain_package_details.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DissociatePackageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DissociatePackageOutput {
    /// Creates a new builder-style object to manufacture [`DissociatePackageOutput`](crate::operation::dissociate_package::DissociatePackageOutput).
    pub fn builder() -> crate::operation::dissociate_package::builders::DissociatePackageOutputBuilder {
        crate::operation::dissociate_package::builders::DissociatePackageOutputBuilder::default()
    }
}

/// A builder for [`DissociatePackageOutput`](crate::operation::dissociate_package::DissociatePackageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DissociatePackageOutputBuilder {
    pub(crate) domain_package_details: ::std::option::Option<crate::types::DomainPackageDetails>,
    _request_id: Option<String>,
}
impl DissociatePackageOutputBuilder {
    /// <p><code>DomainPackageDetails</code></p>
    pub fn domain_package_details(mut self, input: crate::types::DomainPackageDetails) -> Self {
        self.domain_package_details = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>DomainPackageDetails</code></p>
    pub fn set_domain_package_details(mut self, input: ::std::option::Option<crate::types::DomainPackageDetails>) -> Self {
        self.domain_package_details = input;
        self
    }
    /// <p><code>DomainPackageDetails</code></p>
    pub fn get_domain_package_details(&self) -> &::std::option::Option<crate::types::DomainPackageDetails> {
        &self.domain_package_details
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DissociatePackageOutput`](crate::operation::dissociate_package::DissociatePackageOutput).
    pub fn build(self) -> crate::operation::dissociate_package::DissociatePackageOutput {
        crate::operation::dissociate_package::DissociatePackageOutput {
            domain_package_details: self.domain_package_details,
            _request_id: self._request_id,
        }
    }
}
