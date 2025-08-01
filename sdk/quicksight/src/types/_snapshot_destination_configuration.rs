// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains information on the Amazon S3 destinations of the generated snapshot.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnapshotDestinationConfiguration {
    /// <p>A list of <code>SnapshotS3DestinationConfiguration</code> objects that contain Amazon S3 destination configurations. This structure can hold a maximum of 1 <code>S3DestinationConfiguration</code>.</p>
    pub s3_destinations: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotS3DestinationConfiguration>>,
}
impl SnapshotDestinationConfiguration {
    /// <p>A list of <code>SnapshotS3DestinationConfiguration</code> objects that contain Amazon S3 destination configurations. This structure can hold a maximum of 1 <code>S3DestinationConfiguration</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.s3_destinations.is_none()`.
    pub fn s3_destinations(&self) -> &[crate::types::SnapshotS3DestinationConfiguration] {
        self.s3_destinations.as_deref().unwrap_or_default()
    }
}
impl SnapshotDestinationConfiguration {
    /// Creates a new builder-style object to manufacture [`SnapshotDestinationConfiguration`](crate::types::SnapshotDestinationConfiguration).
    pub fn builder() -> crate::types::builders::SnapshotDestinationConfigurationBuilder {
        crate::types::builders::SnapshotDestinationConfigurationBuilder::default()
    }
}

/// A builder for [`SnapshotDestinationConfiguration`](crate::types::SnapshotDestinationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnapshotDestinationConfigurationBuilder {
    pub(crate) s3_destinations: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotS3DestinationConfiguration>>,
}
impl SnapshotDestinationConfigurationBuilder {
    /// Appends an item to `s3_destinations`.
    ///
    /// To override the contents of this collection use [`set_s3_destinations`](Self::set_s3_destinations).
    ///
    /// <p>A list of <code>SnapshotS3DestinationConfiguration</code> objects that contain Amazon S3 destination configurations. This structure can hold a maximum of 1 <code>S3DestinationConfiguration</code>.</p>
    pub fn s3_destinations(mut self, input: crate::types::SnapshotS3DestinationConfiguration) -> Self {
        let mut v = self.s3_destinations.unwrap_or_default();
        v.push(input);
        self.s3_destinations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>SnapshotS3DestinationConfiguration</code> objects that contain Amazon S3 destination configurations. This structure can hold a maximum of 1 <code>S3DestinationConfiguration</code>.</p>
    pub fn set_s3_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotS3DestinationConfiguration>>) -> Self {
        self.s3_destinations = input;
        self
    }
    /// <p>A list of <code>SnapshotS3DestinationConfiguration</code> objects that contain Amazon S3 destination configurations. This structure can hold a maximum of 1 <code>S3DestinationConfiguration</code>.</p>
    pub fn get_s3_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SnapshotS3DestinationConfiguration>> {
        &self.s3_destinations
    }
    /// Consumes the builder and constructs a [`SnapshotDestinationConfiguration`](crate::types::SnapshotDestinationConfiguration).
    pub fn build(self) -> crate::types::SnapshotDestinationConfiguration {
        crate::types::SnapshotDestinationConfiguration {
            s3_destinations: self.s3_destinations,
        }
    }
}
