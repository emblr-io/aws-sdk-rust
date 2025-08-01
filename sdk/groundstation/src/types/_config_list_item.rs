// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An item in a list of <code>Config</code> objects.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfigListItem {
    /// <p>UUID of a <code>Config</code>.</p>
    pub config_id: ::std::option::Option<::std::string::String>,
    /// <p>Type of a <code>Config</code>.</p>
    pub config_type: ::std::option::Option<crate::types::ConfigCapabilityType>,
    /// <p>ARN of a <code>Config</code>.</p>
    pub config_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of a <code>Config</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl ConfigListItem {
    /// <p>UUID of a <code>Config</code>.</p>
    pub fn config_id(&self) -> ::std::option::Option<&str> {
        self.config_id.as_deref()
    }
    /// <p>Type of a <code>Config</code>.</p>
    pub fn config_type(&self) -> ::std::option::Option<&crate::types::ConfigCapabilityType> {
        self.config_type.as_ref()
    }
    /// <p>ARN of a <code>Config</code>.</p>
    pub fn config_arn(&self) -> ::std::option::Option<&str> {
        self.config_arn.as_deref()
    }
    /// <p>Name of a <code>Config</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ConfigListItem {
    /// Creates a new builder-style object to manufacture [`ConfigListItem`](crate::types::ConfigListItem).
    pub fn builder() -> crate::types::builders::ConfigListItemBuilder {
        crate::types::builders::ConfigListItemBuilder::default()
    }
}

/// A builder for [`ConfigListItem`](crate::types::ConfigListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfigListItemBuilder {
    pub(crate) config_id: ::std::option::Option<::std::string::String>,
    pub(crate) config_type: ::std::option::Option<crate::types::ConfigCapabilityType>,
    pub(crate) config_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl ConfigListItemBuilder {
    /// <p>UUID of a <code>Config</code>.</p>
    pub fn config_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>UUID of a <code>Config</code>.</p>
    pub fn set_config_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_id = input;
        self
    }
    /// <p>UUID of a <code>Config</code>.</p>
    pub fn get_config_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_id
    }
    /// <p>Type of a <code>Config</code>.</p>
    pub fn config_type(mut self, input: crate::types::ConfigCapabilityType) -> Self {
        self.config_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of a <code>Config</code>.</p>
    pub fn set_config_type(mut self, input: ::std::option::Option<crate::types::ConfigCapabilityType>) -> Self {
        self.config_type = input;
        self
    }
    /// <p>Type of a <code>Config</code>.</p>
    pub fn get_config_type(&self) -> &::std::option::Option<crate::types::ConfigCapabilityType> {
        &self.config_type
    }
    /// <p>ARN of a <code>Config</code>.</p>
    pub fn config_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of a <code>Config</code>.</p>
    pub fn set_config_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_arn = input;
        self
    }
    /// <p>ARN of a <code>Config</code>.</p>
    pub fn get_config_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_arn
    }
    /// <p>Name of a <code>Config</code>.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of a <code>Config</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of a <code>Config</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`ConfigListItem`](crate::types::ConfigListItem).
    pub fn build(self) -> crate::types::ConfigListItem {
        crate::types::ConfigListItem {
            config_id: self.config_id,
            config_type: self.config_type,
            config_arn: self.config_arn,
            name: self.name,
        }
    }
}
