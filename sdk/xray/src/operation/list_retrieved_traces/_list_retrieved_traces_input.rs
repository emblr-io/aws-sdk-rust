// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRetrievedTracesInput {
    /// <p>Retrieval token.</p>
    pub retrieval_token: ::std::option::Option<::std::string::String>,
    /// <p>Format of the requested traces.</p>
    pub trace_format: ::std::option::Option<crate::types::TraceFormatType>,
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListRetrievedTracesInput {
    /// <p>Retrieval token.</p>
    pub fn retrieval_token(&self) -> ::std::option::Option<&str> {
        self.retrieval_token.as_deref()
    }
    /// <p>Format of the requested traces.</p>
    pub fn trace_format(&self) -> ::std::option::Option<&crate::types::TraceFormatType> {
        self.trace_format.as_ref()
    }
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListRetrievedTracesInput {
    /// Creates a new builder-style object to manufacture [`ListRetrievedTracesInput`](crate::operation::list_retrieved_traces::ListRetrievedTracesInput).
    pub fn builder() -> crate::operation::list_retrieved_traces::builders::ListRetrievedTracesInputBuilder {
        crate::operation::list_retrieved_traces::builders::ListRetrievedTracesInputBuilder::default()
    }
}

/// A builder for [`ListRetrievedTracesInput`](crate::operation::list_retrieved_traces::ListRetrievedTracesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRetrievedTracesInputBuilder {
    pub(crate) retrieval_token: ::std::option::Option<::std::string::String>,
    pub(crate) trace_format: ::std::option::Option<crate::types::TraceFormatType>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListRetrievedTracesInputBuilder {
    /// <p>Retrieval token.</p>
    /// This field is required.
    pub fn retrieval_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.retrieval_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Retrieval token.</p>
    pub fn set_retrieval_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.retrieval_token = input;
        self
    }
    /// <p>Retrieval token.</p>
    pub fn get_retrieval_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.retrieval_token
    }
    /// <p>Format of the requested traces.</p>
    pub fn trace_format(mut self, input: crate::types::TraceFormatType) -> Self {
        self.trace_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>Format of the requested traces.</p>
    pub fn set_trace_format(mut self, input: ::std::option::Option<crate::types::TraceFormatType>) -> Self {
        self.trace_format = input;
        self
    }
    /// <p>Format of the requested traces.</p>
    pub fn get_trace_format(&self) -> &::std::option::Option<crate::types::TraceFormatType> {
        &self.trace_format
    }
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListRetrievedTracesInput`](crate::operation::list_retrieved_traces::ListRetrievedTracesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_retrieved_traces::ListRetrievedTracesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_retrieved_traces::ListRetrievedTracesInput {
            retrieval_token: self.retrieval_token,
            trace_format: self.trace_format,
            next_token: self.next_token,
        })
    }
}
