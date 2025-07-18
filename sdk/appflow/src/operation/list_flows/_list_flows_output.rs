// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFlowsOutput {
    /// <p>The list of flows associated with your account.</p>
    pub flows: ::std::option::Option<::std::vec::Vec<crate::types::FlowDefinition>>,
    /// <p>The pagination token for next page of data.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFlowsOutput {
    /// <p>The list of flows associated with your account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.flows.is_none()`.
    pub fn flows(&self) -> &[crate::types::FlowDefinition] {
        self.flows.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token for next page of data.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFlowsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFlowsOutput {
    /// Creates a new builder-style object to manufacture [`ListFlowsOutput`](crate::operation::list_flows::ListFlowsOutput).
    pub fn builder() -> crate::operation::list_flows::builders::ListFlowsOutputBuilder {
        crate::operation::list_flows::builders::ListFlowsOutputBuilder::default()
    }
}

/// A builder for [`ListFlowsOutput`](crate::operation::list_flows::ListFlowsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFlowsOutputBuilder {
    pub(crate) flows: ::std::option::Option<::std::vec::Vec<crate::types::FlowDefinition>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFlowsOutputBuilder {
    /// Appends an item to `flows`.
    ///
    /// To override the contents of this collection use [`set_flows`](Self::set_flows).
    ///
    /// <p>The list of flows associated with your account.</p>
    pub fn flows(mut self, input: crate::types::FlowDefinition) -> Self {
        let mut v = self.flows.unwrap_or_default();
        v.push(input);
        self.flows = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of flows associated with your account.</p>
    pub fn set_flows(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FlowDefinition>>) -> Self {
        self.flows = input;
        self
    }
    /// <p>The list of flows associated with your account.</p>
    pub fn get_flows(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FlowDefinition>> {
        &self.flows
    }
    /// <p>The pagination token for next page of data.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token for next page of data.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token for next page of data.</p>
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
    /// Consumes the builder and constructs a [`ListFlowsOutput`](crate::operation::list_flows::ListFlowsOutput).
    pub fn build(self) -> crate::operation::list_flows::ListFlowsOutput {
        crate::operation::list_flows::ListFlowsOutput {
            flows: self.flows,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
