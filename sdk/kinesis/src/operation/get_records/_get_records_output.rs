// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output for <code>GetRecords</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRecordsOutput {
    /// <p>The data records retrieved from the shard.</p>
    pub records: ::std::vec::Vec<crate::types::Record>,
    /// <p>The next position in the shard from which to start sequentially reading data records. If set to <code>null</code>, the shard has been closed and the requested iterator does not return any more data.</p>
    pub next_shard_iterator: ::std::option::Option<::std::string::String>,
    /// <p>The number of milliseconds the <code>GetRecords</code> response is from the tip of the stream, indicating how far behind current time the consumer is. A value of zero indicates that record processing is caught up, and there are no new records to process at this moment.</p>
    pub millis_behind_latest: ::std::option::Option<i64>,
    /// <p>The list of the current shard's child shards, returned in the <code>GetRecords</code> API's response only when the end of the current shard is reached.</p>
    pub child_shards: ::std::option::Option<::std::vec::Vec<crate::types::ChildShard>>,
    _request_id: Option<String>,
}
impl GetRecordsOutput {
    /// <p>The data records retrieved from the shard.</p>
    pub fn records(&self) -> &[crate::types::Record] {
        use std::ops::Deref;
        self.records.deref()
    }
    /// <p>The next position in the shard from which to start sequentially reading data records. If set to <code>null</code>, the shard has been closed and the requested iterator does not return any more data.</p>
    pub fn next_shard_iterator(&self) -> ::std::option::Option<&str> {
        self.next_shard_iterator.as_deref()
    }
    /// <p>The number of milliseconds the <code>GetRecords</code> response is from the tip of the stream, indicating how far behind current time the consumer is. A value of zero indicates that record processing is caught up, and there are no new records to process at this moment.</p>
    pub fn millis_behind_latest(&self) -> ::std::option::Option<i64> {
        self.millis_behind_latest
    }
    /// <p>The list of the current shard's child shards, returned in the <code>GetRecords</code> API's response only when the end of the current shard is reached.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.child_shards.is_none()`.
    pub fn child_shards(&self) -> &[crate::types::ChildShard] {
        self.child_shards.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetRecordsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRecordsOutput {
    /// Creates a new builder-style object to manufacture [`GetRecordsOutput`](crate::operation::get_records::GetRecordsOutput).
    pub fn builder() -> crate::operation::get_records::builders::GetRecordsOutputBuilder {
        crate::operation::get_records::builders::GetRecordsOutputBuilder::default()
    }
}

/// A builder for [`GetRecordsOutput`](crate::operation::get_records::GetRecordsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRecordsOutputBuilder {
    pub(crate) records: ::std::option::Option<::std::vec::Vec<crate::types::Record>>,
    pub(crate) next_shard_iterator: ::std::option::Option<::std::string::String>,
    pub(crate) millis_behind_latest: ::std::option::Option<i64>,
    pub(crate) child_shards: ::std::option::Option<::std::vec::Vec<crate::types::ChildShard>>,
    _request_id: Option<String>,
}
impl GetRecordsOutputBuilder {
    /// Appends an item to `records`.
    ///
    /// To override the contents of this collection use [`set_records`](Self::set_records).
    ///
    /// <p>The data records retrieved from the shard.</p>
    pub fn records(mut self, input: crate::types::Record) -> Self {
        let mut v = self.records.unwrap_or_default();
        v.push(input);
        self.records = ::std::option::Option::Some(v);
        self
    }
    /// <p>The data records retrieved from the shard.</p>
    pub fn set_records(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Record>>) -> Self {
        self.records = input;
        self
    }
    /// <p>The data records retrieved from the shard.</p>
    pub fn get_records(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Record>> {
        &self.records
    }
    /// <p>The next position in the shard from which to start sequentially reading data records. If set to <code>null</code>, the shard has been closed and the requested iterator does not return any more data.</p>
    pub fn next_shard_iterator(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_shard_iterator = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next position in the shard from which to start sequentially reading data records. If set to <code>null</code>, the shard has been closed and the requested iterator does not return any more data.</p>
    pub fn set_next_shard_iterator(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_shard_iterator = input;
        self
    }
    /// <p>The next position in the shard from which to start sequentially reading data records. If set to <code>null</code>, the shard has been closed and the requested iterator does not return any more data.</p>
    pub fn get_next_shard_iterator(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_shard_iterator
    }
    /// <p>The number of milliseconds the <code>GetRecords</code> response is from the tip of the stream, indicating how far behind current time the consumer is. A value of zero indicates that record processing is caught up, and there are no new records to process at this moment.</p>
    pub fn millis_behind_latest(mut self, input: i64) -> Self {
        self.millis_behind_latest = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds the <code>GetRecords</code> response is from the tip of the stream, indicating how far behind current time the consumer is. A value of zero indicates that record processing is caught up, and there are no new records to process at this moment.</p>
    pub fn set_millis_behind_latest(mut self, input: ::std::option::Option<i64>) -> Self {
        self.millis_behind_latest = input;
        self
    }
    /// <p>The number of milliseconds the <code>GetRecords</code> response is from the tip of the stream, indicating how far behind current time the consumer is. A value of zero indicates that record processing is caught up, and there are no new records to process at this moment.</p>
    pub fn get_millis_behind_latest(&self) -> &::std::option::Option<i64> {
        &self.millis_behind_latest
    }
    /// Appends an item to `child_shards`.
    ///
    /// To override the contents of this collection use [`set_child_shards`](Self::set_child_shards).
    ///
    /// <p>The list of the current shard's child shards, returned in the <code>GetRecords</code> API's response only when the end of the current shard is reached.</p>
    pub fn child_shards(mut self, input: crate::types::ChildShard) -> Self {
        let mut v = self.child_shards.unwrap_or_default();
        v.push(input);
        self.child_shards = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of the current shard's child shards, returned in the <code>GetRecords</code> API's response only when the end of the current shard is reached.</p>
    pub fn set_child_shards(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ChildShard>>) -> Self {
        self.child_shards = input;
        self
    }
    /// <p>The list of the current shard's child shards, returned in the <code>GetRecords</code> API's response only when the end of the current shard is reached.</p>
    pub fn get_child_shards(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChildShard>> {
        &self.child_shards
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRecordsOutput`](crate::operation::get_records::GetRecordsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`records`](crate::operation::get_records::builders::GetRecordsOutputBuilder::records)
    pub fn build(self) -> ::std::result::Result<crate::operation::get_records::GetRecordsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_records::GetRecordsOutput {
            records: self.records.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "records",
                    "records was not specified but it is required when building GetRecordsOutput",
                )
            })?,
            next_shard_iterator: self.next_shard_iterator,
            millis_behind_latest: self.millis_behind_latest,
            child_shards: self.child_shards,
            _request_id: self._request_id,
        })
    }
}
