// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of <code>ApplicationAttribute</code>s that contains information about the application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplicationConfig {
    /// <p>Contains the attribute name and a list of values for that attribute.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationAttribute>>,
}
impl ApplicationConfig {
    /// <p>Contains the attribute name and a list of values for that attribute.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::ApplicationAttribute] {
        self.attributes.as_deref().unwrap_or_default()
    }
}
impl ApplicationConfig {
    /// Creates a new builder-style object to manufacture [`ApplicationConfig`](crate::types::ApplicationConfig).
    pub fn builder() -> crate::types::builders::ApplicationConfigBuilder {
        crate::types::builders::ApplicationConfigBuilder::default()
    }
}

/// A builder for [`ApplicationConfig`](crate::types::ApplicationConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationConfigBuilder {
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationAttribute>>,
}
impl ApplicationConfigBuilder {
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>Contains the attribute name and a list of values for that attribute.</p>
    pub fn attributes(mut self, input: crate::types::ApplicationAttribute) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains the attribute name and a list of values for that attribute.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationAttribute>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>Contains the attribute name and a list of values for that attribute.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ApplicationAttribute>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`ApplicationConfig`](crate::types::ApplicationConfig).
    pub fn build(self) -> crate::types::ApplicationConfig {
        crate::types::ApplicationConfig { attributes: self.attributes }
    }
}
