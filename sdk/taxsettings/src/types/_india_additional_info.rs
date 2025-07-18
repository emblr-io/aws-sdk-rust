// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Additional tax information in India.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IndiaAdditionalInfo {
    /// <p>India pan information associated with the account.</p>
    pub pan: ::std::option::Option<::std::string::String>,
}
impl IndiaAdditionalInfo {
    /// <p>India pan information associated with the account.</p>
    pub fn pan(&self) -> ::std::option::Option<&str> {
        self.pan.as_deref()
    }
}
impl IndiaAdditionalInfo {
    /// Creates a new builder-style object to manufacture [`IndiaAdditionalInfo`](crate::types::IndiaAdditionalInfo).
    pub fn builder() -> crate::types::builders::IndiaAdditionalInfoBuilder {
        crate::types::builders::IndiaAdditionalInfoBuilder::default()
    }
}

/// A builder for [`IndiaAdditionalInfo`](crate::types::IndiaAdditionalInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IndiaAdditionalInfoBuilder {
    pub(crate) pan: ::std::option::Option<::std::string::String>,
}
impl IndiaAdditionalInfoBuilder {
    /// <p>India pan information associated with the account.</p>
    pub fn pan(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pan = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>India pan information associated with the account.</p>
    pub fn set_pan(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pan = input;
        self
    }
    /// <p>India pan information associated with the account.</p>
    pub fn get_pan(&self) -> &::std::option::Option<::std::string::String> {
        &self.pan
    }
    /// Consumes the builder and constructs a [`IndiaAdditionalInfo`](crate::types::IndiaAdditionalInfo).
    pub fn build(self) -> crate::types::IndiaAdditionalInfo {
        crate::types::IndiaAdditionalInfo { pan: self.pan }
    }
}
