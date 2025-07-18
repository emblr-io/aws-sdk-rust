// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A compute platform.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ComputePlatform {
    /// <p>The compute platform vendor.</p>
    pub vendor: ::std::option::Option<::std::string::String>,
    /// <p>The compute platform product.</p>
    pub product: ::std::option::Option<::std::string::String>,
    /// <p>The compute platform version.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl ComputePlatform {
    /// <p>The compute platform vendor.</p>
    pub fn vendor(&self) -> ::std::option::Option<&str> {
        self.vendor.as_deref()
    }
    /// <p>The compute platform product.</p>
    pub fn product(&self) -> ::std::option::Option<&str> {
        self.product.as_deref()
    }
    /// <p>The compute platform version.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl ComputePlatform {
    /// Creates a new builder-style object to manufacture [`ComputePlatform`](crate::types::ComputePlatform).
    pub fn builder() -> crate::types::builders::ComputePlatformBuilder {
        crate::types::builders::ComputePlatformBuilder::default()
    }
}

/// A builder for [`ComputePlatform`](crate::types::ComputePlatform).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ComputePlatformBuilder {
    pub(crate) vendor: ::std::option::Option<::std::string::String>,
    pub(crate) product: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl ComputePlatformBuilder {
    /// <p>The compute platform vendor.</p>
    pub fn vendor(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vendor = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The compute platform vendor.</p>
    pub fn set_vendor(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vendor = input;
        self
    }
    /// <p>The compute platform vendor.</p>
    pub fn get_vendor(&self) -> &::std::option::Option<::std::string::String> {
        &self.vendor
    }
    /// <p>The compute platform product.</p>
    pub fn product(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The compute platform product.</p>
    pub fn set_product(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product = input;
        self
    }
    /// <p>The compute platform product.</p>
    pub fn get_product(&self) -> &::std::option::Option<::std::string::String> {
        &self.product
    }
    /// <p>The compute platform version.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The compute platform version.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The compute platform version.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`ComputePlatform`](crate::types::ComputePlatform).
    pub fn build(self) -> crate::types::ComputePlatform {
        crate::types::ComputePlatform {
            vendor: self.vendor,
            product: self.product,
            version: self.version,
        }
    }
}
