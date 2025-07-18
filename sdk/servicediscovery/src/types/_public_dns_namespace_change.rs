// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Updated properties for the public DNS namespace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PublicDnsNamespaceChange {
    /// <p>An updated description for the public DNS namespace.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Properties to be updated in the public DNS namespace.</p>
    pub properties: ::std::option::Option<crate::types::PublicDnsNamespacePropertiesChange>,
}
impl PublicDnsNamespaceChange {
    /// <p>An updated description for the public DNS namespace.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Properties to be updated in the public DNS namespace.</p>
    pub fn properties(&self) -> ::std::option::Option<&crate::types::PublicDnsNamespacePropertiesChange> {
        self.properties.as_ref()
    }
}
impl PublicDnsNamespaceChange {
    /// Creates a new builder-style object to manufacture [`PublicDnsNamespaceChange`](crate::types::PublicDnsNamespaceChange).
    pub fn builder() -> crate::types::builders::PublicDnsNamespaceChangeBuilder {
        crate::types::builders::PublicDnsNamespaceChangeBuilder::default()
    }
}

/// A builder for [`PublicDnsNamespaceChange`](crate::types::PublicDnsNamespaceChange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PublicDnsNamespaceChangeBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) properties: ::std::option::Option<crate::types::PublicDnsNamespacePropertiesChange>,
}
impl PublicDnsNamespaceChangeBuilder {
    /// <p>An updated description for the public DNS namespace.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An updated description for the public DNS namespace.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An updated description for the public DNS namespace.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Properties to be updated in the public DNS namespace.</p>
    pub fn properties(mut self, input: crate::types::PublicDnsNamespacePropertiesChange) -> Self {
        self.properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>Properties to be updated in the public DNS namespace.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<crate::types::PublicDnsNamespacePropertiesChange>) -> Self {
        self.properties = input;
        self
    }
    /// <p>Properties to be updated in the public DNS namespace.</p>
    pub fn get_properties(&self) -> &::std::option::Option<crate::types::PublicDnsNamespacePropertiesChange> {
        &self.properties
    }
    /// Consumes the builder and constructs a [`PublicDnsNamespaceChange`](crate::types::PublicDnsNamespaceChange).
    pub fn build(self) -> crate::types::PublicDnsNamespaceChange {
        crate::types::PublicDnsNamespaceChange {
            description: self.description,
            properties: self.properties,
        }
    }
}
