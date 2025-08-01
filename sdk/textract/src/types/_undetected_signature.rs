// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure containing information about an undetected signature on a page where it was expected but not found.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UndetectedSignature {
    /// <p>The page where a signature was expected but not found.</p>
    pub page: ::std::option::Option<i32>,
}
impl UndetectedSignature {
    /// <p>The page where a signature was expected but not found.</p>
    pub fn page(&self) -> ::std::option::Option<i32> {
        self.page
    }
}
impl UndetectedSignature {
    /// Creates a new builder-style object to manufacture [`UndetectedSignature`](crate::types::UndetectedSignature).
    pub fn builder() -> crate::types::builders::UndetectedSignatureBuilder {
        crate::types::builders::UndetectedSignatureBuilder::default()
    }
}

/// A builder for [`UndetectedSignature`](crate::types::UndetectedSignature).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UndetectedSignatureBuilder {
    pub(crate) page: ::std::option::Option<i32>,
}
impl UndetectedSignatureBuilder {
    /// <p>The page where a signature was expected but not found.</p>
    pub fn page(mut self, input: i32) -> Self {
        self.page = ::std::option::Option::Some(input);
        self
    }
    /// <p>The page where a signature was expected but not found.</p>
    pub fn set_page(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page = input;
        self
    }
    /// <p>The page where a signature was expected but not found.</p>
    pub fn get_page(&self) -> &::std::option::Option<i32> {
        &self.page
    }
    /// Consumes the builder and constructs a [`UndetectedSignature`](crate::types::UndetectedSignature).
    pub fn build(self) -> crate::types::UndetectedSignature {
        crate::types::UndetectedSignature { page: self.page }
    }
}
