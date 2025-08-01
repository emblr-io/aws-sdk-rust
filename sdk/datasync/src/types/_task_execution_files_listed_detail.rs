// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The number of objects that DataSync finds at your locations.</p><note>
/// <p>Applies only to <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Enhanced mode tasks</a>.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskExecutionFilesListedDetail {
    /// <p>The number of objects that DataSync finds at your source location.</p>
    /// <ul>
    /// <li>
    /// <p>With a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">manifest</a>, DataSync lists only what's in your manifest (and not everything at your source location).</p></li>
    /// <li>
    /// <p>With an include <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">filter</a>, DataSync lists only what matches the filter at your source location.</p></li>
    /// <li>
    /// <p>With an exclude filter, DataSync lists everything at your source location before applying the filter.</p></li>
    /// </ul>
    pub at_source: i64,
    /// <p>The number of objects that DataSync finds at your destination location. This counter is only applicable if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html#task-option-file-object-handling">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub at_destination_for_delete: i64,
}
impl TaskExecutionFilesListedDetail {
    /// <p>The number of objects that DataSync finds at your source location.</p>
    /// <ul>
    /// <li>
    /// <p>With a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">manifest</a>, DataSync lists only what's in your manifest (and not everything at your source location).</p></li>
    /// <li>
    /// <p>With an include <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">filter</a>, DataSync lists only what matches the filter at your source location.</p></li>
    /// <li>
    /// <p>With an exclude filter, DataSync lists everything at your source location before applying the filter.</p></li>
    /// </ul>
    pub fn at_source(&self) -> i64 {
        self.at_source
    }
    /// <p>The number of objects that DataSync finds at your destination location. This counter is only applicable if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html#task-option-file-object-handling">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn at_destination_for_delete(&self) -> i64 {
        self.at_destination_for_delete
    }
}
impl TaskExecutionFilesListedDetail {
    /// Creates a new builder-style object to manufacture [`TaskExecutionFilesListedDetail`](crate::types::TaskExecutionFilesListedDetail).
    pub fn builder() -> crate::types::builders::TaskExecutionFilesListedDetailBuilder {
        crate::types::builders::TaskExecutionFilesListedDetailBuilder::default()
    }
}

/// A builder for [`TaskExecutionFilesListedDetail`](crate::types::TaskExecutionFilesListedDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskExecutionFilesListedDetailBuilder {
    pub(crate) at_source: ::std::option::Option<i64>,
    pub(crate) at_destination_for_delete: ::std::option::Option<i64>,
}
impl TaskExecutionFilesListedDetailBuilder {
    /// <p>The number of objects that DataSync finds at your source location.</p>
    /// <ul>
    /// <li>
    /// <p>With a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">manifest</a>, DataSync lists only what's in your manifest (and not everything at your source location).</p></li>
    /// <li>
    /// <p>With an include <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">filter</a>, DataSync lists only what matches the filter at your source location.</p></li>
    /// <li>
    /// <p>With an exclude filter, DataSync lists everything at your source location before applying the filter.</p></li>
    /// </ul>
    pub fn at_source(mut self, input: i64) -> Self {
        self.at_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of objects that DataSync finds at your source location.</p>
    /// <ul>
    /// <li>
    /// <p>With a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">manifest</a>, DataSync lists only what's in your manifest (and not everything at your source location).</p></li>
    /// <li>
    /// <p>With an include <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">filter</a>, DataSync lists only what matches the filter at your source location.</p></li>
    /// <li>
    /// <p>With an exclude filter, DataSync lists everything at your source location before applying the filter.</p></li>
    /// </ul>
    pub fn set_at_source(mut self, input: ::std::option::Option<i64>) -> Self {
        self.at_source = input;
        self
    }
    /// <p>The number of objects that DataSync finds at your source location.</p>
    /// <ul>
    /// <li>
    /// <p>With a <a href="https://docs.aws.amazon.com/datasync/latest/userguide/transferring-with-manifest.html">manifest</a>, DataSync lists only what's in your manifest (and not everything at your source location).</p></li>
    /// <li>
    /// <p>With an include <a href="https://docs.aws.amazon.com/datasync/latest/userguide/filtering.html">filter</a>, DataSync lists only what matches the filter at your source location.</p></li>
    /// <li>
    /// <p>With an exclude filter, DataSync lists everything at your source location before applying the filter.</p></li>
    /// </ul>
    pub fn get_at_source(&self) -> &::std::option::Option<i64> {
        &self.at_source
    }
    /// <p>The number of objects that DataSync finds at your destination location. This counter is only applicable if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html#task-option-file-object-handling">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn at_destination_for_delete(mut self, input: i64) -> Self {
        self.at_destination_for_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of objects that DataSync finds at your destination location. This counter is only applicable if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html#task-option-file-object-handling">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn set_at_destination_for_delete(mut self, input: ::std::option::Option<i64>) -> Self {
        self.at_destination_for_delete = input;
        self
    }
    /// <p>The number of objects that DataSync finds at your destination location. This counter is only applicable if you <a href="https://docs.aws.amazon.com/datasync/latest/userguide/configure-metadata.html#task-option-file-object-handling">configure your task</a> to delete data in the destination that isn't in the source.</p>
    pub fn get_at_destination_for_delete(&self) -> &::std::option::Option<i64> {
        &self.at_destination_for_delete
    }
    /// Consumes the builder and constructs a [`TaskExecutionFilesListedDetail`](crate::types::TaskExecutionFilesListedDetail).
    pub fn build(self) -> crate::types::TaskExecutionFilesListedDetail {
        crate::types::TaskExecutionFilesListedDetail {
            at_source: self.at_source.unwrap_or_default(),
            at_destination_for_delete: self.at_destination_for_delete.unwrap_or_default(),
        }
    }
}
