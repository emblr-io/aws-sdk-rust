// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the version control configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VersionControlInfo {
    /// <p>The type of version control.</p>
    pub version_control_type: ::std::option::Option<crate::types::VersionControlType>,
    /// <p>The time when the version control system was last configured.</p>
    pub version_control_configuration_time_stamp: ::std::option::Option<::std::string::String>,
}
impl VersionControlInfo {
    /// <p>The type of version control.</p>
    pub fn version_control_type(&self) -> ::std::option::Option<&crate::types::VersionControlType> {
        self.version_control_type.as_ref()
    }
    /// <p>The time when the version control system was last configured.</p>
    pub fn version_control_configuration_time_stamp(&self) -> ::std::option::Option<&str> {
        self.version_control_configuration_time_stamp.as_deref()
    }
}
impl VersionControlInfo {
    /// Creates a new builder-style object to manufacture [`VersionControlInfo`](crate::types::VersionControlInfo).
    pub fn builder() -> crate::types::builders::VersionControlInfoBuilder {
        crate::types::builders::VersionControlInfoBuilder::default()
    }
}

/// A builder for [`VersionControlInfo`](crate::types::VersionControlInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VersionControlInfoBuilder {
    pub(crate) version_control_type: ::std::option::Option<crate::types::VersionControlType>,
    pub(crate) version_control_configuration_time_stamp: ::std::option::Option<::std::string::String>,
}
impl VersionControlInfoBuilder {
    /// <p>The type of version control.</p>
    pub fn version_control_type(mut self, input: crate::types::VersionControlType) -> Self {
        self.version_control_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of version control.</p>
    pub fn set_version_control_type(mut self, input: ::std::option::Option<crate::types::VersionControlType>) -> Self {
        self.version_control_type = input;
        self
    }
    /// <p>The type of version control.</p>
    pub fn get_version_control_type(&self) -> &::std::option::Option<crate::types::VersionControlType> {
        &self.version_control_type
    }
    /// <p>The time when the version control system was last configured.</p>
    pub fn version_control_configuration_time_stamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_control_configuration_time_stamp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time when the version control system was last configured.</p>
    pub fn set_version_control_configuration_time_stamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_control_configuration_time_stamp = input;
        self
    }
    /// <p>The time when the version control system was last configured.</p>
    pub fn get_version_control_configuration_time_stamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_control_configuration_time_stamp
    }
    /// Consumes the builder and constructs a [`VersionControlInfo`](crate::types::VersionControlInfo).
    pub fn build(self) -> crate::types::VersionControlInfo {
        crate::types::VersionControlInfo {
            version_control_type: self.version_control_type,
            version_control_configuration_time_stamp: self.version_control_configuration_time_stamp,
        }
    }
}
