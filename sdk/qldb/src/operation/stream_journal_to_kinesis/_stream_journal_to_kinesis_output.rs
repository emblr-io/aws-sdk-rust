// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StreamJournalToKinesisOutput {
    /// <p>The UUID (represented in Base62-encoded text) that QLDB assigns to each QLDB journal stream.</p>
    pub stream_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StreamJournalToKinesisOutput {
    /// <p>The UUID (represented in Base62-encoded text) that QLDB assigns to each QLDB journal stream.</p>
    pub fn stream_id(&self) -> ::std::option::Option<&str> {
        self.stream_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StreamJournalToKinesisOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StreamJournalToKinesisOutput {
    /// Creates a new builder-style object to manufacture [`StreamJournalToKinesisOutput`](crate::operation::stream_journal_to_kinesis::StreamJournalToKinesisOutput).
    pub fn builder() -> crate::operation::stream_journal_to_kinesis::builders::StreamJournalToKinesisOutputBuilder {
        crate::operation::stream_journal_to_kinesis::builders::StreamJournalToKinesisOutputBuilder::default()
    }
}

/// A builder for [`StreamJournalToKinesisOutput`](crate::operation::stream_journal_to_kinesis::StreamJournalToKinesisOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StreamJournalToKinesisOutputBuilder {
    pub(crate) stream_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StreamJournalToKinesisOutputBuilder {
    /// <p>The UUID (represented in Base62-encoded text) that QLDB assigns to each QLDB journal stream.</p>
    pub fn stream_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) that QLDB assigns to each QLDB journal stream.</p>
    pub fn set_stream_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_id = input;
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) that QLDB assigns to each QLDB journal stream.</p>
    pub fn get_stream_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StreamJournalToKinesisOutput`](crate::operation::stream_journal_to_kinesis::StreamJournalToKinesisOutput).
    pub fn build(self) -> crate::operation::stream_journal_to_kinesis::StreamJournalToKinesisOutput {
        crate::operation::stream_journal_to_kinesis::StreamJournalToKinesisOutput {
            stream_id: self.stream_id,
            _request_id: self._request_id,
        }
    }
}
