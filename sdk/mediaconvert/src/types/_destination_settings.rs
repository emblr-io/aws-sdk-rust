// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings associated with the destination. Will vary based on the type of destination
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DestinationSettings {
    /// Settings associated with S3 destination
    pub s3_settings: ::std::option::Option<crate::types::S3DestinationSettings>,
}
impl DestinationSettings {
    /// Settings associated with S3 destination
    pub fn s3_settings(&self) -> ::std::option::Option<&crate::types::S3DestinationSettings> {
        self.s3_settings.as_ref()
    }
}
impl DestinationSettings {
    /// Creates a new builder-style object to manufacture [`DestinationSettings`](crate::types::DestinationSettings).
    pub fn builder() -> crate::types::builders::DestinationSettingsBuilder {
        crate::types::builders::DestinationSettingsBuilder::default()
    }
}

/// A builder for [`DestinationSettings`](crate::types::DestinationSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationSettingsBuilder {
    pub(crate) s3_settings: ::std::option::Option<crate::types::S3DestinationSettings>,
}
impl DestinationSettingsBuilder {
    /// Settings associated with S3 destination
    pub fn s3_settings(mut self, input: crate::types::S3DestinationSettings) -> Self {
        self.s3_settings = ::std::option::Option::Some(input);
        self
    }
    /// Settings associated with S3 destination
    pub fn set_s3_settings(mut self, input: ::std::option::Option<crate::types::S3DestinationSettings>) -> Self {
        self.s3_settings = input;
        self
    }
    /// Settings associated with S3 destination
    pub fn get_s3_settings(&self) -> &::std::option::Option<crate::types::S3DestinationSettings> {
        &self.s3_settings
    }
    /// Consumes the builder and constructs a [`DestinationSettings`](crate::types::DestinationSettings).
    pub fn build(self) -> crate::types::DestinationSettings {
        crate::types::DestinationSettings {
            s3_settings: self.s3_settings,
        }
    }
}
