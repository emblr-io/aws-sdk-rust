// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAccessEntryOutput {
    /// <p>The ARN of the IAM principal for the <code>AccessEntry</code>.</p>
    pub access_entry: ::std::option::Option<crate::types::AccessEntry>,
    _request_id: Option<String>,
}
impl UpdateAccessEntryOutput {
    /// <p>The ARN of the IAM principal for the <code>AccessEntry</code>.</p>
    pub fn access_entry(&self) -> ::std::option::Option<&crate::types::AccessEntry> {
        self.access_entry.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateAccessEntryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateAccessEntryOutput {
    /// Creates a new builder-style object to manufacture [`UpdateAccessEntryOutput`](crate::operation::update_access_entry::UpdateAccessEntryOutput).
    pub fn builder() -> crate::operation::update_access_entry::builders::UpdateAccessEntryOutputBuilder {
        crate::operation::update_access_entry::builders::UpdateAccessEntryOutputBuilder::default()
    }
}

/// A builder for [`UpdateAccessEntryOutput`](crate::operation::update_access_entry::UpdateAccessEntryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAccessEntryOutputBuilder {
    pub(crate) access_entry: ::std::option::Option<crate::types::AccessEntry>,
    _request_id: Option<String>,
}
impl UpdateAccessEntryOutputBuilder {
    /// <p>The ARN of the IAM principal for the <code>AccessEntry</code>.</p>
    pub fn access_entry(mut self, input: crate::types::AccessEntry) -> Self {
        self.access_entry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ARN of the IAM principal for the <code>AccessEntry</code>.</p>
    pub fn set_access_entry(mut self, input: ::std::option::Option<crate::types::AccessEntry>) -> Self {
        self.access_entry = input;
        self
    }
    /// <p>The ARN of the IAM principal for the <code>AccessEntry</code>.</p>
    pub fn get_access_entry(&self) -> &::std::option::Option<crate::types::AccessEntry> {
        &self.access_entry
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateAccessEntryOutput`](crate::operation::update_access_entry::UpdateAccessEntryOutput).
    pub fn build(self) -> crate::operation::update_access_entry::UpdateAccessEntryOutput {
        crate::operation::update_access_entry::UpdateAccessEntryOutput {
            access_entry: self.access_entry,
            _request_id: self._request_id,
        }
    }
}
