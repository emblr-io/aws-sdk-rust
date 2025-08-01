// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetExportSnapshotRecordsOutput {
    /// <p>A list of objects describing the export snapshot records.</p>
    pub export_snapshot_records: ::std::option::Option<::std::vec::Vec<crate::types::ExportSnapshotRecord>>,
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetExportSnapshotRecords</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetExportSnapshotRecordsOutput {
    /// <p>A list of objects describing the export snapshot records.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.export_snapshot_records.is_none()`.
    pub fn export_snapshot_records(&self) -> &[crate::types::ExportSnapshotRecord] {
        self.export_snapshot_records.as_deref().unwrap_or_default()
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetExportSnapshotRecords</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetExportSnapshotRecordsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetExportSnapshotRecordsOutput {
    /// Creates a new builder-style object to manufacture [`GetExportSnapshotRecordsOutput`](crate::operation::get_export_snapshot_records::GetExportSnapshotRecordsOutput).
    pub fn builder() -> crate::operation::get_export_snapshot_records::builders::GetExportSnapshotRecordsOutputBuilder {
        crate::operation::get_export_snapshot_records::builders::GetExportSnapshotRecordsOutputBuilder::default()
    }
}

/// A builder for [`GetExportSnapshotRecordsOutput`](crate::operation::get_export_snapshot_records::GetExportSnapshotRecordsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetExportSnapshotRecordsOutputBuilder {
    pub(crate) export_snapshot_records: ::std::option::Option<::std::vec::Vec<crate::types::ExportSnapshotRecord>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetExportSnapshotRecordsOutputBuilder {
    /// Appends an item to `export_snapshot_records`.
    ///
    /// To override the contents of this collection use [`set_export_snapshot_records`](Self::set_export_snapshot_records).
    ///
    /// <p>A list of objects describing the export snapshot records.</p>
    pub fn export_snapshot_records(mut self, input: crate::types::ExportSnapshotRecord) -> Self {
        let mut v = self.export_snapshot_records.unwrap_or_default();
        v.push(input);
        self.export_snapshot_records = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of objects describing the export snapshot records.</p>
    pub fn set_export_snapshot_records(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExportSnapshotRecord>>) -> Self {
        self.export_snapshot_records = input;
        self
    }
    /// <p>A list of objects describing the export snapshot records.</p>
    pub fn get_export_snapshot_records(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExportSnapshotRecord>> {
        &self.export_snapshot_records
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetExportSnapshotRecords</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetExportSnapshotRecords</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to advance to the next page of results from your request.</p>
    /// <p>A next page token is not returned if there are no more results to display.</p>
    /// <p>To get the next page of results, perform another <code>GetExportSnapshotRecords</code> request and specify the next page token using the <code>pageToken</code> parameter.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetExportSnapshotRecordsOutput`](crate::operation::get_export_snapshot_records::GetExportSnapshotRecordsOutput).
    pub fn build(self) -> crate::operation::get_export_snapshot_records::GetExportSnapshotRecordsOutput {
        crate::operation::get_export_snapshot_records::GetExportSnapshotRecordsOutput {
            export_snapshot_records: self.export_snapshot_records,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
