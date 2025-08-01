// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the data repository association's automatic import policy. The AutoImportPolicy defines how Amazon FSx keeps your file metadata and directory listings up to date by importing changes to your Amazon FSx for Lustre file system as you modify objects in a linked S3 bucket.</p>
/// <p>The <code>AutoImportPolicy</code> is only supported on Amazon FSx for Lustre file systems with a data repository association.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoImportPolicy {
    /// <p>The <code>AutoImportPolicy</code> can have the following event values:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code> - Amazon FSx automatically imports metadata of files added to the linked S3 bucket that do not currently exist in the FSx file system.</p></li>
    /// <li>
    /// <p><code>CHANGED</code> - Amazon FSx automatically updates file metadata and invalidates existing file content on the file system as files change in the data repository.</p></li>
    /// <li>
    /// <p><code>DELETED</code> - Amazon FSx automatically deletes files on the file system as corresponding files are deleted in the data repository.</p></li>
    /// </ul>
    /// <p>You can define any combination of event types for your <code>AutoImportPolicy</code>.</p>
    pub events: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>,
}
impl AutoImportPolicy {
    /// <p>The <code>AutoImportPolicy</code> can have the following event values:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code> - Amazon FSx automatically imports metadata of files added to the linked S3 bucket that do not currently exist in the FSx file system.</p></li>
    /// <li>
    /// <p><code>CHANGED</code> - Amazon FSx automatically updates file metadata and invalidates existing file content on the file system as files change in the data repository.</p></li>
    /// <li>
    /// <p><code>DELETED</code> - Amazon FSx automatically deletes files on the file system as corresponding files are deleted in the data repository.</p></li>
    /// </ul>
    /// <p>You can define any combination of event types for your <code>AutoImportPolicy</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.events.is_none()`.
    pub fn events(&self) -> &[crate::types::EventType] {
        self.events.as_deref().unwrap_or_default()
    }
}
impl AutoImportPolicy {
    /// Creates a new builder-style object to manufacture [`AutoImportPolicy`](crate::types::AutoImportPolicy).
    pub fn builder() -> crate::types::builders::AutoImportPolicyBuilder {
        crate::types::builders::AutoImportPolicyBuilder::default()
    }
}

/// A builder for [`AutoImportPolicy`](crate::types::AutoImportPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoImportPolicyBuilder {
    pub(crate) events: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>,
}
impl AutoImportPolicyBuilder {
    /// Appends an item to `events`.
    ///
    /// To override the contents of this collection use [`set_events`](Self::set_events).
    ///
    /// <p>The <code>AutoImportPolicy</code> can have the following event values:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code> - Amazon FSx automatically imports metadata of files added to the linked S3 bucket that do not currently exist in the FSx file system.</p></li>
    /// <li>
    /// <p><code>CHANGED</code> - Amazon FSx automatically updates file metadata and invalidates existing file content on the file system as files change in the data repository.</p></li>
    /// <li>
    /// <p><code>DELETED</code> - Amazon FSx automatically deletes files on the file system as corresponding files are deleted in the data repository.</p></li>
    /// </ul>
    /// <p>You can define any combination of event types for your <code>AutoImportPolicy</code>.</p>
    pub fn events(mut self, input: crate::types::EventType) -> Self {
        let mut v = self.events.unwrap_or_default();
        v.push(input);
        self.events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <code>AutoImportPolicy</code> can have the following event values:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code> - Amazon FSx automatically imports metadata of files added to the linked S3 bucket that do not currently exist in the FSx file system.</p></li>
    /// <li>
    /// <p><code>CHANGED</code> - Amazon FSx automatically updates file metadata and invalidates existing file content on the file system as files change in the data repository.</p></li>
    /// <li>
    /// <p><code>DELETED</code> - Amazon FSx automatically deletes files on the file system as corresponding files are deleted in the data repository.</p></li>
    /// </ul>
    /// <p>You can define any combination of event types for your <code>AutoImportPolicy</code>.</p>
    pub fn set_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>) -> Self {
        self.events = input;
        self
    }
    /// <p>The <code>AutoImportPolicy</code> can have the following event values:</p>
    /// <ul>
    /// <li>
    /// <p><code>NEW</code> - Amazon FSx automatically imports metadata of files added to the linked S3 bucket that do not currently exist in the FSx file system.</p></li>
    /// <li>
    /// <p><code>CHANGED</code> - Amazon FSx automatically updates file metadata and invalidates existing file content on the file system as files change in the data repository.</p></li>
    /// <li>
    /// <p><code>DELETED</code> - Amazon FSx automatically deletes files on the file system as corresponding files are deleted in the data repository.</p></li>
    /// </ul>
    /// <p>You can define any combination of event types for your <code>AutoImportPolicy</code>.</p>
    pub fn get_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventType>> {
        &self.events
    }
    /// Consumes the builder and constructs a [`AutoImportPolicy`](crate::types::AutoImportPolicy).
    pub fn build(self) -> crate::types::AutoImportPolicy {
        crate::types::AutoImportPolicy { events: self.events }
    }
}
