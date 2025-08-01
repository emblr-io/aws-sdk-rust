// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutPartnerEventsOutput {
    /// <p>The number of events from this operation that could not be written to the partner event bus.</p>
    pub failed_entry_count: i32,
    /// <p>The list of events from this operation that were successfully written to the partner event bus.</p>
    pub entries: ::std::option::Option<::std::vec::Vec<crate::types::PutPartnerEventsResultEntry>>,
    _request_id: Option<String>,
}
impl PutPartnerEventsOutput {
    /// <p>The number of events from this operation that could not be written to the partner event bus.</p>
    pub fn failed_entry_count(&self) -> i32 {
        self.failed_entry_count
    }
    /// <p>The list of events from this operation that were successfully written to the partner event bus.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.entries.is_none()`.
    pub fn entries(&self) -> &[crate::types::PutPartnerEventsResultEntry] {
        self.entries.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for PutPartnerEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutPartnerEventsOutput {
    /// Creates a new builder-style object to manufacture [`PutPartnerEventsOutput`](crate::operation::put_partner_events::PutPartnerEventsOutput).
    pub fn builder() -> crate::operation::put_partner_events::builders::PutPartnerEventsOutputBuilder {
        crate::operation::put_partner_events::builders::PutPartnerEventsOutputBuilder::default()
    }
}

/// A builder for [`PutPartnerEventsOutput`](crate::operation::put_partner_events::PutPartnerEventsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutPartnerEventsOutputBuilder {
    pub(crate) failed_entry_count: ::std::option::Option<i32>,
    pub(crate) entries: ::std::option::Option<::std::vec::Vec<crate::types::PutPartnerEventsResultEntry>>,
    _request_id: Option<String>,
}
impl PutPartnerEventsOutputBuilder {
    /// <p>The number of events from this operation that could not be written to the partner event bus.</p>
    pub fn failed_entry_count(mut self, input: i32) -> Self {
        self.failed_entry_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of events from this operation that could not be written to the partner event bus.</p>
    pub fn set_failed_entry_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed_entry_count = input;
        self
    }
    /// <p>The number of events from this operation that could not be written to the partner event bus.</p>
    pub fn get_failed_entry_count(&self) -> &::std::option::Option<i32> {
        &self.failed_entry_count
    }
    /// Appends an item to `entries`.
    ///
    /// To override the contents of this collection use [`set_entries`](Self::set_entries).
    ///
    /// <p>The list of events from this operation that were successfully written to the partner event bus.</p>
    pub fn entries(mut self, input: crate::types::PutPartnerEventsResultEntry) -> Self {
        let mut v = self.entries.unwrap_or_default();
        v.push(input);
        self.entries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of events from this operation that were successfully written to the partner event bus.</p>
    pub fn set_entries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PutPartnerEventsResultEntry>>) -> Self {
        self.entries = input;
        self
    }
    /// <p>The list of events from this operation that were successfully written to the partner event bus.</p>
    pub fn get_entries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PutPartnerEventsResultEntry>> {
        &self.entries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutPartnerEventsOutput`](crate::operation::put_partner_events::PutPartnerEventsOutput).
    pub fn build(self) -> crate::operation::put_partner_events::PutPartnerEventsOutput {
        crate::operation::put_partner_events::PutPartnerEventsOutput {
            failed_entry_count: self.failed_entry_count.unwrap_or_default(),
            entries: self.entries,
            _request_id: self._request_id,
        }
    }
}
