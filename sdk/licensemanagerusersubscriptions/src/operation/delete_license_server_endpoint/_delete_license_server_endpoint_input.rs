// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLicenseServerEndpointInput {
    /// <p>The Amazon Resource Name (ARN) that identifies the <code>LicenseServerEndpoint</code> resource to delete.</p>
    pub license_server_endpoint_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of License Server that the delete request refers to.</p>
    pub server_type: ::std::option::Option<crate::types::ServerType>,
}
impl DeleteLicenseServerEndpointInput {
    /// <p>The Amazon Resource Name (ARN) that identifies the <code>LicenseServerEndpoint</code> resource to delete.</p>
    pub fn license_server_endpoint_arn(&self) -> ::std::option::Option<&str> {
        self.license_server_endpoint_arn.as_deref()
    }
    /// <p>The type of License Server that the delete request refers to.</p>
    pub fn server_type(&self) -> ::std::option::Option<&crate::types::ServerType> {
        self.server_type.as_ref()
    }
}
impl DeleteLicenseServerEndpointInput {
    /// Creates a new builder-style object to manufacture [`DeleteLicenseServerEndpointInput`](crate::operation::delete_license_server_endpoint::DeleteLicenseServerEndpointInput).
    pub fn builder() -> crate::operation::delete_license_server_endpoint::builders::DeleteLicenseServerEndpointInputBuilder {
        crate::operation::delete_license_server_endpoint::builders::DeleteLicenseServerEndpointInputBuilder::default()
    }
}

/// A builder for [`DeleteLicenseServerEndpointInput`](crate::operation::delete_license_server_endpoint::DeleteLicenseServerEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLicenseServerEndpointInputBuilder {
    pub(crate) license_server_endpoint_arn: ::std::option::Option<::std::string::String>,
    pub(crate) server_type: ::std::option::Option<crate::types::ServerType>,
}
impl DeleteLicenseServerEndpointInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies the <code>LicenseServerEndpoint</code> resource to delete.</p>
    /// This field is required.
    pub fn license_server_endpoint_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_server_endpoint_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the <code>LicenseServerEndpoint</code> resource to delete.</p>
    pub fn set_license_server_endpoint_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_server_endpoint_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the <code>LicenseServerEndpoint</code> resource to delete.</p>
    pub fn get_license_server_endpoint_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_server_endpoint_arn
    }
    /// <p>The type of License Server that the delete request refers to.</p>
    /// This field is required.
    pub fn server_type(mut self, input: crate::types::ServerType) -> Self {
        self.server_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of License Server that the delete request refers to.</p>
    pub fn set_server_type(mut self, input: ::std::option::Option<crate::types::ServerType>) -> Self {
        self.server_type = input;
        self
    }
    /// <p>The type of License Server that the delete request refers to.</p>
    pub fn get_server_type(&self) -> &::std::option::Option<crate::types::ServerType> {
        &self.server_type
    }
    /// Consumes the builder and constructs a [`DeleteLicenseServerEndpointInput`](crate::operation::delete_license_server_endpoint::DeleteLicenseServerEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_license_server_endpoint::DeleteLicenseServerEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_license_server_endpoint::DeleteLicenseServerEndpointInput {
            license_server_endpoint_arn: self.license_server_endpoint_arn,
            server_type: self.server_type,
        })
    }
}
