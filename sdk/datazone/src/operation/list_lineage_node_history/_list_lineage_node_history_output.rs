// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLineageNodeHistoryOutput {
    /// <p>The nodes returned by the ListLineageNodeHistory action.</p>
    pub nodes: ::std::option::Option<::std::vec::Vec<crate::types::LineageNodeSummary>>,
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLineageNodeHistoryOutput {
    /// <p>The nodes returned by the ListLineageNodeHistory action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.nodes.is_none()`.
    pub fn nodes(&self) -> &[crate::types::LineageNodeSummary] {
        self.nodes.as_deref().unwrap_or_default()
    }
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListLineageNodeHistoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListLineageNodeHistoryOutput {
    /// Creates a new builder-style object to manufacture [`ListLineageNodeHistoryOutput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryOutput).
    pub fn builder() -> crate::operation::list_lineage_node_history::builders::ListLineageNodeHistoryOutputBuilder {
        crate::operation::list_lineage_node_history::builders::ListLineageNodeHistoryOutputBuilder::default()
    }
}

/// A builder for [`ListLineageNodeHistoryOutput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLineageNodeHistoryOutputBuilder {
    pub(crate) nodes: ::std::option::Option<::std::vec::Vec<crate::types::LineageNodeSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLineageNodeHistoryOutputBuilder {
    /// Appends an item to `nodes`.
    ///
    /// To override the contents of this collection use [`set_nodes`](Self::set_nodes).
    ///
    /// <p>The nodes returned by the ListLineageNodeHistory action.</p>
    pub fn nodes(mut self, input: crate::types::LineageNodeSummary) -> Self {
        let mut v = self.nodes.unwrap_or_default();
        v.push(input);
        self.nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The nodes returned by the ListLineageNodeHistory action.</p>
    pub fn set_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LineageNodeSummary>>) -> Self {
        self.nodes = input;
        self
    }
    /// <p>The nodes returned by the ListLineageNodeHistory action.</p>
    pub fn get_nodes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LineageNodeSummary>> {
        &self.nodes
    }
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
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
    /// Consumes the builder and constructs a [`ListLineageNodeHistoryOutput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryOutput).
    pub fn build(self) -> crate::operation::list_lineage_node_history::ListLineageNodeHistoryOutput {
        crate::operation::list_lineage_node_history::ListLineageNodeHistoryOutput {
            nodes: self.nodes,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
