// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJournalKinesisStreamInput {
    /// <p>The name of the ledger.</p>
    pub ledger_name: ::std::option::Option<::std::string::String>,
    /// <p>The UUID (represented in Base62-encoded text) of the QLDB journal stream to describe.</p>
    pub stream_id: ::std::option::Option<::std::string::String>,
}
impl DescribeJournalKinesisStreamInput {
    /// <p>The name of the ledger.</p>
    pub fn ledger_name(&self) -> ::std::option::Option<&str> {
        self.ledger_name.as_deref()
    }
    /// <p>The UUID (represented in Base62-encoded text) of the QLDB journal stream to describe.</p>
    pub fn stream_id(&self) -> ::std::option::Option<&str> {
        self.stream_id.as_deref()
    }
}
impl DescribeJournalKinesisStreamInput {
    /// Creates a new builder-style object to manufacture [`DescribeJournalKinesisStreamInput`](crate::operation::describe_journal_kinesis_stream::DescribeJournalKinesisStreamInput).
    pub fn builder() -> crate::operation::describe_journal_kinesis_stream::builders::DescribeJournalKinesisStreamInputBuilder {
        crate::operation::describe_journal_kinesis_stream::builders::DescribeJournalKinesisStreamInputBuilder::default()
    }
}

/// A builder for [`DescribeJournalKinesisStreamInput`](crate::operation::describe_journal_kinesis_stream::DescribeJournalKinesisStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJournalKinesisStreamInputBuilder {
    pub(crate) ledger_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_id: ::std::option::Option<::std::string::String>,
}
impl DescribeJournalKinesisStreamInputBuilder {
    /// <p>The name of the ledger.</p>
    /// This field is required.
    pub fn ledger_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ledger_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ledger.</p>
    pub fn set_ledger_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ledger_name = input;
        self
    }
    /// <p>The name of the ledger.</p>
    pub fn get_ledger_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.ledger_name
    }
    /// <p>The UUID (represented in Base62-encoded text) of the QLDB journal stream to describe.</p>
    /// This field is required.
    pub fn stream_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) of the QLDB journal stream to describe.</p>
    pub fn set_stream_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_id = input;
        self
    }
    /// <p>The UUID (represented in Base62-encoded text) of the QLDB journal stream to describe.</p>
    pub fn get_stream_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_id
    }
    /// Consumes the builder and constructs a [`DescribeJournalKinesisStreamInput`](crate::operation::describe_journal_kinesis_stream::DescribeJournalKinesisStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_journal_kinesis_stream::DescribeJournalKinesisStreamInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_journal_kinesis_stream::DescribeJournalKinesisStreamInput {
            ledger_name: self.ledger_name,
            stream_id: self.stream_id,
        })
    }
}
