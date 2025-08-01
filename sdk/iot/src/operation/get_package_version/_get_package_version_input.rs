// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPackageVersionInput {
    /// <p>The name of the associated package.</p>
    pub package_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the target package version.</p>
    pub version_name: ::std::option::Option<::std::string::String>,
}
impl GetPackageVersionInput {
    /// <p>The name of the associated package.</p>
    pub fn package_name(&self) -> ::std::option::Option<&str> {
        self.package_name.as_deref()
    }
    /// <p>The name of the target package version.</p>
    pub fn version_name(&self) -> ::std::option::Option<&str> {
        self.version_name.as_deref()
    }
}
impl GetPackageVersionInput {
    /// Creates a new builder-style object to manufacture [`GetPackageVersionInput`](crate::operation::get_package_version::GetPackageVersionInput).
    pub fn builder() -> crate::operation::get_package_version::builders::GetPackageVersionInputBuilder {
        crate::operation::get_package_version::builders::GetPackageVersionInputBuilder::default()
    }
}

/// A builder for [`GetPackageVersionInput`](crate::operation::get_package_version::GetPackageVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPackageVersionInputBuilder {
    pub(crate) package_name: ::std::option::Option<::std::string::String>,
    pub(crate) version_name: ::std::option::Option<::std::string::String>,
}
impl GetPackageVersionInputBuilder {
    /// <p>The name of the associated package.</p>
    /// This field is required.
    pub fn package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the associated package.</p>
    pub fn set_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.package_name = input;
        self
    }
    /// <p>The name of the associated package.</p>
    pub fn get_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.package_name
    }
    /// <p>The name of the target package version.</p>
    /// This field is required.
    pub fn version_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target package version.</p>
    pub fn set_version_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_name = input;
        self
    }
    /// <p>The name of the target package version.</p>
    pub fn get_version_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_name
    }
    /// Consumes the builder and constructs a [`GetPackageVersionInput`](crate::operation::get_package_version::GetPackageVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_package_version::GetPackageVersionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_package_version::GetPackageVersionInput {
            package_name: self.package_name,
            version_name: self.version_name,
        })
    }
}
