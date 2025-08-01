// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveTargetsOutput {
    /// <p>The number of failed entries.</p>
    pub failed_entry_count: i32,
    /// <p>The failed target entries.</p>
    pub failed_entries: ::std::option::Option<::std::vec::Vec<crate::types::RemoveTargetsResultEntry>>,
    _request_id: Option<String>,
}
impl RemoveTargetsOutput {
    /// <p>The number of failed entries.</p>
    pub fn failed_entry_count(&self) -> i32 {
        self.failed_entry_count
    }
    /// <p>The failed target entries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_entries.is_none()`.
    pub fn failed_entries(&self) -> &[crate::types::RemoveTargetsResultEntry] {
        self.failed_entries.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for RemoveTargetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RemoveTargetsOutput {
    /// Creates a new builder-style object to manufacture [`RemoveTargetsOutput`](crate::operation::remove_targets::RemoveTargetsOutput).
    pub fn builder() -> crate::operation::remove_targets::builders::RemoveTargetsOutputBuilder {
        crate::operation::remove_targets::builders::RemoveTargetsOutputBuilder::default()
    }
}

/// A builder for [`RemoveTargetsOutput`](crate::operation::remove_targets::RemoveTargetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveTargetsOutputBuilder {
    pub(crate) failed_entry_count: ::std::option::Option<i32>,
    pub(crate) failed_entries: ::std::option::Option<::std::vec::Vec<crate::types::RemoveTargetsResultEntry>>,
    _request_id: Option<String>,
}
impl RemoveTargetsOutputBuilder {
    /// <p>The number of failed entries.</p>
    pub fn failed_entry_count(mut self, input: i32) -> Self {
        self.failed_entry_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of failed entries.</p>
    pub fn set_failed_entry_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed_entry_count = input;
        self
    }
    /// <p>The number of failed entries.</p>
    pub fn get_failed_entry_count(&self) -> &::std::option::Option<i32> {
        &self.failed_entry_count
    }
    /// Appends an item to `failed_entries`.
    ///
    /// To override the contents of this collection use [`set_failed_entries`](Self::set_failed_entries).
    ///
    /// <p>The failed target entries.</p>
    pub fn failed_entries(mut self, input: crate::types::RemoveTargetsResultEntry) -> Self {
        let mut v = self.failed_entries.unwrap_or_default();
        v.push(input);
        self.failed_entries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The failed target entries.</p>
    pub fn set_failed_entries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RemoveTargetsResultEntry>>) -> Self {
        self.failed_entries = input;
        self
    }
    /// <p>The failed target entries.</p>
    pub fn get_failed_entries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RemoveTargetsResultEntry>> {
        &self.failed_entries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RemoveTargetsOutput`](crate::operation::remove_targets::RemoveTargetsOutput).
    pub fn build(self) -> crate::operation::remove_targets::RemoveTargetsOutput {
        crate::operation::remove_targets::RemoveTargetsOutput {
            failed_entry_count: self.failed_entry_count.unwrap_or_default(),
            failed_entries: self.failed_entries,
            _request_id: self._request_id,
        }
    }
}
