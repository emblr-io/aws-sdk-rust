// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelOpenCypherQueryOutput {
    /// <p>The cancellation status of the openCypher query.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The cancelation payload for the openCypher query.</p>
    pub payload: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl CancelOpenCypherQueryOutput {
    /// <p>The cancellation status of the openCypher query.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The cancelation payload for the openCypher query.</p>
    pub fn payload(&self) -> ::std::option::Option<bool> {
        self.payload
    }
}
impl ::aws_types::request_id::RequestId for CancelOpenCypherQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelOpenCypherQueryOutput {
    /// Creates a new builder-style object to manufacture [`CancelOpenCypherQueryOutput`](crate::operation::cancel_open_cypher_query::CancelOpenCypherQueryOutput).
    pub fn builder() -> crate::operation::cancel_open_cypher_query::builders::CancelOpenCypherQueryOutputBuilder {
        crate::operation::cancel_open_cypher_query::builders::CancelOpenCypherQueryOutputBuilder::default()
    }
}

/// A builder for [`CancelOpenCypherQueryOutput`](crate::operation::cancel_open_cypher_query::CancelOpenCypherQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelOpenCypherQueryOutputBuilder {
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) payload: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl CancelOpenCypherQueryOutputBuilder {
    /// <p>The cancellation status of the openCypher query.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cancellation status of the openCypher query.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The cancellation status of the openCypher query.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The cancelation payload for the openCypher query.</p>
    pub fn payload(mut self, input: bool) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>The cancelation payload for the openCypher query.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<bool>) -> Self {
        self.payload = input;
        self
    }
    /// <p>The cancelation payload for the openCypher query.</p>
    pub fn get_payload(&self) -> &::std::option::Option<bool> {
        &self.payload
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelOpenCypherQueryOutput`](crate::operation::cancel_open_cypher_query::CancelOpenCypherQueryOutput).
    pub fn build(self) -> crate::operation::cancel_open_cypher_query::CancelOpenCypherQueryOutput {
        crate::operation::cancel_open_cypher_query::CancelOpenCypherQueryOutput {
            status: self.status,
            payload: self.payload,
            _request_id: self._request_id,
        }
    }
}
