// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure that consists of name and type of volume.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Volume {
    /// <p>A unique identifier for the volume.</p>
    pub volume_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of file system volume. Currently, FinSpace only supports <code>NAS_1</code> volume type.</p>
    pub volume_type: ::std::option::Option<crate::types::VolumeType>,
}
impl Volume {
    /// <p>A unique identifier for the volume.</p>
    pub fn volume_name(&self) -> ::std::option::Option<&str> {
        self.volume_name.as_deref()
    }
    /// <p>The type of file system volume. Currently, FinSpace only supports <code>NAS_1</code> volume type.</p>
    pub fn volume_type(&self) -> ::std::option::Option<&crate::types::VolumeType> {
        self.volume_type.as_ref()
    }
}
impl Volume {
    /// Creates a new builder-style object to manufacture [`Volume`](crate::types::Volume).
    pub fn builder() -> crate::types::builders::VolumeBuilder {
        crate::types::builders::VolumeBuilder::default()
    }
}

/// A builder for [`Volume`](crate::types::Volume).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VolumeBuilder {
    pub(crate) volume_name: ::std::option::Option<::std::string::String>,
    pub(crate) volume_type: ::std::option::Option<crate::types::VolumeType>,
}
impl VolumeBuilder {
    /// <p>A unique identifier for the volume.</p>
    pub fn volume_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the volume.</p>
    pub fn set_volume_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_name = input;
        self
    }
    /// <p>A unique identifier for the volume.</p>
    pub fn get_volume_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_name
    }
    /// <p>The type of file system volume. Currently, FinSpace only supports <code>NAS_1</code> volume type.</p>
    pub fn volume_type(mut self, input: crate::types::VolumeType) -> Self {
        self.volume_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of file system volume. Currently, FinSpace only supports <code>NAS_1</code> volume type.</p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<crate::types::VolumeType>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>The type of file system volume. Currently, FinSpace only supports <code>NAS_1</code> volume type.</p>
    pub fn get_volume_type(&self) -> &::std::option::Option<crate::types::VolumeType> {
        &self.volume_type
    }
    /// Consumes the builder and constructs a [`Volume`](crate::types::Volume).
    pub fn build(self) -> crate::types::Volume {
        crate::types::Volume {
            volume_name: self.volume_name,
            volume_type: self.volume_type,
        }
    }
}
