// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLicenseEndpointInput {
    /// <p>The license endpoint ID.</p>
    pub license_endpoint_id: ::std::option::Option<::std::string::String>,
}
impl GetLicenseEndpointInput {
    /// <p>The license endpoint ID.</p>
    pub fn license_endpoint_id(&self) -> ::std::option::Option<&str> {
        self.license_endpoint_id.as_deref()
    }
}
impl GetLicenseEndpointInput {
    /// Creates a new builder-style object to manufacture [`GetLicenseEndpointInput`](crate::operation::get_license_endpoint::GetLicenseEndpointInput).
    pub fn builder() -> crate::operation::get_license_endpoint::builders::GetLicenseEndpointInputBuilder {
        crate::operation::get_license_endpoint::builders::GetLicenseEndpointInputBuilder::default()
    }
}

/// A builder for [`GetLicenseEndpointInput`](crate::operation::get_license_endpoint::GetLicenseEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLicenseEndpointInputBuilder {
    pub(crate) license_endpoint_id: ::std::option::Option<::std::string::String>,
}
impl GetLicenseEndpointInputBuilder {
    /// <p>The license endpoint ID.</p>
    /// This field is required.
    pub fn license_endpoint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_endpoint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The license endpoint ID.</p>
    pub fn set_license_endpoint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_endpoint_id = input;
        self
    }
    /// <p>The license endpoint ID.</p>
    pub fn get_license_endpoint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_endpoint_id
    }
    /// Consumes the builder and constructs a [`GetLicenseEndpointInput`](crate::operation::get_license_endpoint::GetLicenseEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_license_endpoint::GetLicenseEndpointInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_license_endpoint::GetLicenseEndpointInput {
            license_endpoint_id: self.license_endpoint_id,
        })
    }
}
