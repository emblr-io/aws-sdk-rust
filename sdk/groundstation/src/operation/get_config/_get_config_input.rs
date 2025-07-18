// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfigInput {
    /// <p>UUID of a <code>Config</code>.</p>
    pub config_id: ::std::option::Option<::std::string::String>,
    /// <p>Type of a <code>Config</code>.</p>
    pub config_type: ::std::option::Option<crate::types::ConfigCapabilityType>,
}
impl GetConfigInput {
    /// <p>UUID of a <code>Config</code>.</p>
    pub fn config_id(&self) -> ::std::option::Option<&str> {
        self.config_id.as_deref()
    }
    /// <p>Type of a <code>Config</code>.</p>
    pub fn config_type(&self) -> ::std::option::Option<&crate::types::ConfigCapabilityType> {
        self.config_type.as_ref()
    }
}
impl GetConfigInput {
    /// Creates a new builder-style object to manufacture [`GetConfigInput`](crate::operation::get_config::GetConfigInput).
    pub fn builder() -> crate::operation::get_config::builders::GetConfigInputBuilder {
        crate::operation::get_config::builders::GetConfigInputBuilder::default()
    }
}

/// A builder for [`GetConfigInput`](crate::operation::get_config::GetConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfigInputBuilder {
    pub(crate) config_id: ::std::option::Option<::std::string::String>,
    pub(crate) config_type: ::std::option::Option<crate::types::ConfigCapabilityType>,
}
impl GetConfigInputBuilder {
    /// <p>UUID of a <code>Config</code>.</p>
    /// This field is required.
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
    /// This field is required.
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
    /// Consumes the builder and constructs a [`GetConfigInput`](crate::operation::get_config::GetConfigInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_config::GetConfigInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_config::GetConfigInput {
            config_id: self.config_id,
            config_type: self.config_type,
        })
    }
}
