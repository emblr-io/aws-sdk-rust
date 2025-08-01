// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTraceRetrievalInput {
    /// <p>Specify the trace IDs of the traces to be retrieved.</p>
    pub trace_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The start of the time range to retrieve traces. The range is inclusive, so the specified start time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time range to retrieve traces. The range is inclusive, so the specified end time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl StartTraceRetrievalInput {
    /// <p>Specify the trace IDs of the traces to be retrieved.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.trace_ids.is_none()`.
    pub fn trace_ids(&self) -> &[::std::string::String] {
        self.trace_ids.as_deref().unwrap_or_default()
    }
    /// <p>The start of the time range to retrieve traces. The range is inclusive, so the specified start time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end of the time range to retrieve traces. The range is inclusive, so the specified end time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl StartTraceRetrievalInput {
    /// Creates a new builder-style object to manufacture [`StartTraceRetrievalInput`](crate::operation::start_trace_retrieval::StartTraceRetrievalInput).
    pub fn builder() -> crate::operation::start_trace_retrieval::builders::StartTraceRetrievalInputBuilder {
        crate::operation::start_trace_retrieval::builders::StartTraceRetrievalInputBuilder::default()
    }
}

/// A builder for [`StartTraceRetrievalInput`](crate::operation::start_trace_retrieval::StartTraceRetrievalInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTraceRetrievalInputBuilder {
    pub(crate) trace_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl StartTraceRetrievalInputBuilder {
    /// Appends an item to `trace_ids`.
    ///
    /// To override the contents of this collection use [`set_trace_ids`](Self::set_trace_ids).
    ///
    /// <p>Specify the trace IDs of the traces to be retrieved.</p>
    pub fn trace_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.trace_ids.unwrap_or_default();
        v.push(input.into());
        self.trace_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specify the trace IDs of the traces to be retrieved.</p>
    pub fn set_trace_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.trace_ids = input;
        self
    }
    /// <p>Specify the trace IDs of the traces to be retrieved.</p>
    pub fn get_trace_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.trace_ids
    }
    /// <p>The start of the time range to retrieve traces. The range is inclusive, so the specified start time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time range to retrieve traces. The range is inclusive, so the specified start time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start of the time range to retrieve traces. The range is inclusive, so the specified start time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end of the time range to retrieve traces. The range is inclusive, so the specified end time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time range to retrieve traces. The range is inclusive, so the specified end time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end of the time range to retrieve traces. The range is inclusive, so the specified end time is included in the query. Specified as epoch time, the number of seconds since January 1, 1970, 00:00:00 UTC.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`StartTraceRetrievalInput`](crate::operation::start_trace_retrieval::StartTraceRetrievalInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_trace_retrieval::StartTraceRetrievalInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_trace_retrieval::StartTraceRetrievalInput {
            trace_ids: self.trace_ids,
            start_time: self.start_time,
            end_time: self.end_time,
        })
    }
}
