// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLicenseUsageInput {
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub license_arn: ::std::option::Option<::std::string::String>,
}
impl GetLicenseUsageInput {
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn license_arn(&self) -> ::std::option::Option<&str> {
        self.license_arn.as_deref()
    }
}
impl GetLicenseUsageInput {
    /// Creates a new builder-style object to manufacture [`GetLicenseUsageInput`](crate::operation::get_license_usage::GetLicenseUsageInput).
    pub fn builder() -> crate::operation::get_license_usage::builders::GetLicenseUsageInputBuilder {
        crate::operation::get_license_usage::builders::GetLicenseUsageInputBuilder::default()
    }
}

/// A builder for [`GetLicenseUsageInput`](crate::operation::get_license_usage::GetLicenseUsageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLicenseUsageInputBuilder {
    pub(crate) license_arn: ::std::option::Option<::std::string::String>,
}
impl GetLicenseUsageInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    /// This field is required.
    pub fn license_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn set_license_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license.</p>
    pub fn get_license_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_arn
    }
    /// Consumes the builder and constructs a [`GetLicenseUsageInput`](crate::operation::get_license_usage::GetLicenseUsageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_license_usage::GetLicenseUsageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_license_usage::GetLicenseUsageInput {
            license_arn: self.license_arn,
        })
    }
}
