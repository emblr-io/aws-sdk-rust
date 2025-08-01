// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRetrievedTracesGraphOutput {
    /// <p>Status of the retrieval.</p>
    pub retrieval_status: ::std::option::Option<crate::types::RetrievalStatus>,
    /// <p>Retrieved services.</p>
    pub services: ::std::option::Option<::std::vec::Vec<crate::types::RetrievedService>>,
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRetrievedTracesGraphOutput {
    /// <p>Status of the retrieval.</p>
    pub fn retrieval_status(&self) -> ::std::option::Option<&crate::types::RetrievalStatus> {
        self.retrieval_status.as_ref()
    }
    /// <p>Retrieved services.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.services.is_none()`.
    pub fn services(&self) -> &[crate::types::RetrievedService] {
        self.services.as_deref().unwrap_or_default()
    }
    /// <p>Specify the pagination token returned by a previous request to retrieve the next page of indexes.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetRetrievedTracesGraphOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRetrievedTracesGraphOutput {
    /// Creates a new builder-style object to manufacture [`GetRetrievedTracesGraphOutput`](crate::operation::get_retrieved_traces_graph::GetRetrievedTracesGraphOutput).
    pub fn builder() -> crate::operation::get_retrieved_traces_graph::builders::GetRetrievedTracesGraphOutputBuilder {
        crate::operation::get_retrieved_traces_graph::builders::GetRetrievedTracesGraphOutputBuilder::default()
    }
}

/// A builder for [`GetRetrievedTracesGraphOutput`](crate::operation::get_retrieved_traces_graph::GetRetrievedTracesGraphOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRetrievedTracesGraphOutputBuilder {
    pub(crate) retrieval_status: ::std::option::Option<crate::types::RetrievalStatus>,
    pub(crate) services: ::std::option::Option<::std::vec::Vec<crate::types::RetrievedService>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetRetrievedTracesGraphOutputBuilder {
    /// <p>Status of the retrieval.</p>
    pub fn retrieval_status(mut self, input: crate::types::RetrievalStatus) -> Self {
        self.retrieval_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the retrieval.</p>
    pub fn set_retrieval_status(mut self, input: ::std::option::Option<crate::types::RetrievalStatus>) -> Self {
        self.retrieval_status = input;
        self
    }
    /// <p>Status of the retrieval.</p>
    pub fn get_retrieval_status(&self) -> &::std::option::Option<crate::types::RetrievalStatus> {
        &self.retrieval_status
    }
    /// Appends an item to `services`.
    ///
    /// To override the contents of this collection use [`set_services`](Self::set_services).
    ///
    /// <p>Retrieved services.</p>
    pub fn services(mut self, input: crate::types::RetrievedService) -> Self {
        let mut v = self.services.unwrap_or_default();
        v.push(input);
        self.services = ::std::option::Option::Some(v);
        self
    }
    /// <p>Retrieved services.</p>
    pub fn set_services(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RetrievedService>>) -> Self {
        self.services = input;
        self
    }
    /// <p>Retrieved services.</p>
    pub fn get_services(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RetrievedService>> {
        &self.services
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRetrievedTracesGraphOutput`](crate::operation::get_retrieved_traces_graph::GetRetrievedTracesGraphOutput).
    pub fn build(self) -> crate::operation::get_retrieved_traces_graph::GetRetrievedTracesGraphOutput {
        crate::operation::get_retrieved_traces_graph::GetRetrievedTracesGraphOutput {
            retrieval_status: self.retrieval_status,
            services: self.services,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
