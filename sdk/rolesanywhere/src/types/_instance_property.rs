// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A key-value pair you set that identifies a property of the authenticating instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceProperty {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub seen_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of instanceProperty objects.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub failed: ::std::option::Option<bool>,
}
impl InstanceProperty {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn seen_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.seen_at.as_ref()
    }
    /// <p>A list of instanceProperty objects.</p>
    pub fn properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.properties.as_ref()
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn failed(&self) -> ::std::option::Option<bool> {
        self.failed
    }
}
impl InstanceProperty {
    /// Creates a new builder-style object to manufacture [`InstanceProperty`](crate::types::InstanceProperty).
    pub fn builder() -> crate::types::builders::InstancePropertyBuilder {
        crate::types::builders::InstancePropertyBuilder::default()
    }
}

/// A builder for [`InstanceProperty`](crate::types::InstanceProperty).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstancePropertyBuilder {
    pub(crate) seen_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) failed: ::std::option::Option<bool>,
}
impl InstancePropertyBuilder {
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn seen_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.seen_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn set_seen_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.seen_at = input;
        self
    }
    /// <p>The ISO-8601 time stamp of when the certificate was last used in a temporary credential request.</p>
    pub fn get_seen_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.seen_at
    }
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>A list of instanceProperty objects.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of instanceProperty objects.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>A list of instanceProperty objects.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.properties
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn failed(mut self, input: bool) -> Self {
        self.failed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn set_failed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.failed = input;
        self
    }
    /// <p>Indicates whether the temporary credential request was successful.</p>
    pub fn get_failed(&self) -> &::std::option::Option<bool> {
        &self.failed
    }
    /// Consumes the builder and constructs a [`InstanceProperty`](crate::types::InstanceProperty).
    pub fn build(self) -> crate::types::InstanceProperty {
        crate::types::InstanceProperty {
            seen_at: self.seen_at,
            properties: self.properties,
            failed: self.failed,
        }
    }
}
