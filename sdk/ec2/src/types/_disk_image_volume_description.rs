// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a disk image volume.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DiskImageVolumeDescription {
    /// <p>The volume identifier.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The size of the volume, in GiB.</p>
    pub size: ::std::option::Option<i64>,
}
impl DiskImageVolumeDescription {
    /// <p>The volume identifier.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn size(&self) -> ::std::option::Option<i64> {
        self.size
    }
}
impl DiskImageVolumeDescription {
    /// Creates a new builder-style object to manufacture [`DiskImageVolumeDescription`](crate::types::DiskImageVolumeDescription).
    pub fn builder() -> crate::types::builders::DiskImageVolumeDescriptionBuilder {
        crate::types::builders::DiskImageVolumeDescriptionBuilder::default()
    }
}

/// A builder for [`DiskImageVolumeDescription`](crate::types::DiskImageVolumeDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DiskImageVolumeDescriptionBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
}
impl DiskImageVolumeDescriptionBuilder {
    /// <p>The volume identifier.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The volume identifier.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The volume identifier.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// Consumes the builder and constructs a [`DiskImageVolumeDescription`](crate::types::DiskImageVolumeDescription).
    pub fn build(self) -> crate::types::DiskImageVolumeDescription {
        crate::types::DiskImageVolumeDescription {
            id: self.id,
            size: self.size,
        }
    }
}
