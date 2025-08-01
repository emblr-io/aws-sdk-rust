// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnapshotOptions {
    /// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
    pub automated_snapshot_start_hour: ::std::option::Option<i32>,
}
impl SnapshotOptions {
    /// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
    pub fn automated_snapshot_start_hour(&self) -> ::std::option::Option<i32> {
        self.automated_snapshot_start_hour
    }
}
impl SnapshotOptions {
    /// Creates a new builder-style object to manufacture [`SnapshotOptions`](crate::types::SnapshotOptions).
    pub fn builder() -> crate::types::builders::SnapshotOptionsBuilder {
        crate::types::builders::SnapshotOptionsBuilder::default()
    }
}

/// A builder for [`SnapshotOptions`](crate::types::SnapshotOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnapshotOptionsBuilder {
    pub(crate) automated_snapshot_start_hour: ::std::option::Option<i32>,
}
impl SnapshotOptionsBuilder {
    /// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
    pub fn automated_snapshot_start_hour(mut self, input: i32) -> Self {
        self.automated_snapshot_start_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
    pub fn set_automated_snapshot_start_hour(mut self, input: ::std::option::Option<i32>) -> Self {
        self.automated_snapshot_start_hour = input;
        self
    }
    /// <p>Specifies the time, in UTC format, when the service takes a daily automated snapshot of the specified Elasticsearch domain. Default value is <code>0</code> hours.</p>
    pub fn get_automated_snapshot_start_hour(&self) -> &::std::option::Option<i32> {
        &self.automated_snapshot_start_hour
    }
    /// Consumes the builder and constructs a [`SnapshotOptions`](crate::types::SnapshotOptions).
    pub fn build(self) -> crate::types::SnapshotOptions {
        crate::types::SnapshotOptions {
            automated_snapshot_start_hour: self.automated_snapshot_start_hour,
        }
    }
}
