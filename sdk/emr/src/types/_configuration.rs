// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>Amazon EMR releases 4.x or later.</p>
/// </note>
/// <p>An optional configuration specification to be used when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html">Configuring Applications</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Configuration {
    /// <p>The classification within a configuration.</p>
    pub classification: ::std::option::Option<::std::string::String>,
    /// <p>A list of additional configurations to apply within a configuration object.</p>
    pub configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    /// <p>A set of properties specified within a configuration classification.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Configuration {
    /// <p>The classification within a configuration.</p>
    pub fn classification(&self) -> ::std::option::Option<&str> {
        self.classification.as_deref()
    }
    /// <p>A list of additional configurations to apply within a configuration object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configurations.is_none()`.
    pub fn configurations(&self) -> &[crate::types::Configuration] {
        self.configurations.as_deref().unwrap_or_default()
    }
    /// <p>A set of properties specified within a configuration classification.</p>
    pub fn properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.properties.as_ref()
    }
}
impl Configuration {
    /// Creates a new builder-style object to manufacture [`Configuration`](crate::types::Configuration).
    pub fn builder() -> crate::types::builders::ConfigurationBuilder {
        crate::types::builders::ConfigurationBuilder::default()
    }
}

/// A builder for [`Configuration`](crate::types::Configuration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfigurationBuilder {
    pub(crate) classification: ::std::option::Option<::std::string::String>,
    pub(crate) configurations: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ConfigurationBuilder {
    /// <p>The classification within a configuration.</p>
    pub fn classification(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.classification = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The classification within a configuration.</p>
    pub fn set_classification(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.classification = input;
        self
    }
    /// <p>The classification within a configuration.</p>
    pub fn get_classification(&self) -> &::std::option::Option<::std::string::String> {
        &self.classification
    }
    /// Appends an item to `configurations`.
    ///
    /// To override the contents of this collection use [`set_configurations`](Self::set_configurations).
    ///
    /// <p>A list of additional configurations to apply within a configuration object.</p>
    pub fn configurations(mut self, input: crate::types::Configuration) -> Self {
        let mut v = self.configurations.unwrap_or_default();
        v.push(input);
        self.configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of additional configurations to apply within a configuration object.</p>
    pub fn set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>) -> Self {
        self.configurations = input;
        self
    }
    /// <p>A list of additional configurations to apply within a configuration object.</p>
    pub fn get_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Configuration>> {
        &self.configurations
    }
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>A set of properties specified within a configuration classification.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of properties specified within a configuration classification.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>A set of properties specified within a configuration classification.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.properties
    }
    /// Consumes the builder and constructs a [`Configuration`](crate::types::Configuration).
    pub fn build(self) -> crate::types::Configuration {
        crate::types::Configuration {
            classification: self.classification,
            configurations: self.configurations,
            properties: self.properties,
        }
    }
}
