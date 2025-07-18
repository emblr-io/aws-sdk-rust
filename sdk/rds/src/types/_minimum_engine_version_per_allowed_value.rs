// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The minimum DB engine version required for each corresponding allowed value for an option setting.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MinimumEngineVersionPerAllowedValue {
    /// <p>The allowed value for an option setting.</p>
    pub allowed_value: ::std::option::Option<::std::string::String>,
    /// <p>The minimum DB engine version required for the allowed value.</p>
    pub minimum_engine_version: ::std::option::Option<::std::string::String>,
}
impl MinimumEngineVersionPerAllowedValue {
    /// <p>The allowed value for an option setting.</p>
    pub fn allowed_value(&self) -> ::std::option::Option<&str> {
        self.allowed_value.as_deref()
    }
    /// <p>The minimum DB engine version required for the allowed value.</p>
    pub fn minimum_engine_version(&self) -> ::std::option::Option<&str> {
        self.minimum_engine_version.as_deref()
    }
}
impl MinimumEngineVersionPerAllowedValue {
    /// Creates a new builder-style object to manufacture [`MinimumEngineVersionPerAllowedValue`](crate::types::MinimumEngineVersionPerAllowedValue).
    pub fn builder() -> crate::types::builders::MinimumEngineVersionPerAllowedValueBuilder {
        crate::types::builders::MinimumEngineVersionPerAllowedValueBuilder::default()
    }
}

/// A builder for [`MinimumEngineVersionPerAllowedValue`](crate::types::MinimumEngineVersionPerAllowedValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MinimumEngineVersionPerAllowedValueBuilder {
    pub(crate) allowed_value: ::std::option::Option<::std::string::String>,
    pub(crate) minimum_engine_version: ::std::option::Option<::std::string::String>,
}
impl MinimumEngineVersionPerAllowedValueBuilder {
    /// <p>The allowed value for an option setting.</p>
    pub fn allowed_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allowed_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The allowed value for an option setting.</p>
    pub fn set_allowed_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allowed_value = input;
        self
    }
    /// <p>The allowed value for an option setting.</p>
    pub fn get_allowed_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.allowed_value
    }
    /// <p>The minimum DB engine version required for the allowed value.</p>
    pub fn minimum_engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.minimum_engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The minimum DB engine version required for the allowed value.</p>
    pub fn set_minimum_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.minimum_engine_version = input;
        self
    }
    /// <p>The minimum DB engine version required for the allowed value.</p>
    pub fn get_minimum_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.minimum_engine_version
    }
    /// Consumes the builder and constructs a [`MinimumEngineVersionPerAllowedValue`](crate::types::MinimumEngineVersionPerAllowedValue).
    pub fn build(self) -> crate::types::MinimumEngineVersionPerAllowedValue {
        crate::types::MinimumEngineVersionPerAllowedValue {
            allowed_value: self.allowed_value,
            minimum_engine_version: self.minimum_engine_version,
        }
    }
}
