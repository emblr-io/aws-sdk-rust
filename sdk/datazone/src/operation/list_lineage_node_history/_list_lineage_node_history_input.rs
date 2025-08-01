// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLineageNodeHistoryInput {
    /// <p>The ID of the domain where you want to list the history of the specified data lineage node.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of history items to return in a single call to ListLineageNodeHistory. When the number of memberships to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the data lineage node whose history you want to list.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The direction of the data lineage node refers to the lineage node having neighbors in that direction. For example, if direction is <code>UPSTREAM</code>, the <code>ListLineageNodeHistory</code> API responds with historical versions with upstream neighbors only.</p>
    pub direction: ::std::option::Option<crate::types::EdgeDirection>,
    /// <p>Specifies whether the action is to return data lineage node history from the time after the event timestamp.</p>
    pub event_timestamp_gte: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies whether the action is to return data lineage node history from the time prior of the event timestamp.</p>
    pub event_timestamp_lte: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The order by which you want data lineage node history to be sorted.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListLineageNodeHistoryInput {
    /// <p>The ID of the domain where you want to list the history of the specified data lineage node.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The maximum number of history items to return in a single call to ListLineageNodeHistory. When the number of memberships to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>When the number of history items is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of items, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The ID of the data lineage node whose history you want to list.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The direction of the data lineage node refers to the lineage node having neighbors in that direction. For example, if direction is <code>UPSTREAM</code>, the <code>ListLineageNodeHistory</code> API responds with historical versions with upstream neighbors only.</p>
    pub fn direction(&self) -> ::std::option::Option<&crate::types::EdgeDirection> {
        self.direction.as_ref()
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time after the event timestamp.</p>
    pub fn event_timestamp_gte(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.event_timestamp_gte.as_ref()
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time prior of the event timestamp.</p>
    pub fn event_timestamp_lte(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.event_timestamp_lte.as_ref()
    }
    /// <p>The order by which you want data lineage node history to be sorted.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
}
impl ListLineageNodeHistoryInput {
    /// Creates a new builder-style object to manufacture [`ListLineageNodeHistoryInput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryInput).
    pub fn builder() -> crate::operation::list_lineage_node_history::builders::ListLineageNodeHistoryInputBuilder {
        crate::operation::list_lineage_node_history::builders::ListLineageNodeHistoryInputBuilder::default()
    }
}

/// A builder for [`ListLineageNodeHistoryInput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLineageNodeHistoryInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) direction: ::std::option::Option<crate::types::EdgeDirection>,
    pub(crate) event_timestamp_gte: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) event_timestamp_lte: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl ListLineageNodeHistoryInputBuilder {
    /// <p>The ID of the domain where you want to list the history of the specified data lineage node.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain where you want to list the history of the specified data lineage node.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the domain where you want to list the history of the specified data lineage node.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The maximum number of history items to return in a single call to ListLineageNodeHistory. When the number of memberships to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of history items to return in a single call to ListLineageNodeHistory. When the number of memberships to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of history items to return in a single call to ListLineageNodeHistory. When the number of memberships to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListLineageNodeHistory to list the next set of items.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
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
    /// <p>The ID of the data lineage node whose history you want to list.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the data lineage node whose history you want to list.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The ID of the data lineage node whose history you want to list.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The direction of the data lineage node refers to the lineage node having neighbors in that direction. For example, if direction is <code>UPSTREAM</code>, the <code>ListLineageNodeHistory</code> API responds with historical versions with upstream neighbors only.</p>
    pub fn direction(mut self, input: crate::types::EdgeDirection) -> Self {
        self.direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The direction of the data lineage node refers to the lineage node having neighbors in that direction. For example, if direction is <code>UPSTREAM</code>, the <code>ListLineageNodeHistory</code> API responds with historical versions with upstream neighbors only.</p>
    pub fn set_direction(mut self, input: ::std::option::Option<crate::types::EdgeDirection>) -> Self {
        self.direction = input;
        self
    }
    /// <p>The direction of the data lineage node refers to the lineage node having neighbors in that direction. For example, if direction is <code>UPSTREAM</code>, the <code>ListLineageNodeHistory</code> API responds with historical versions with upstream neighbors only.</p>
    pub fn get_direction(&self) -> &::std::option::Option<crate::types::EdgeDirection> {
        &self.direction
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time after the event timestamp.</p>
    pub fn event_timestamp_gte(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.event_timestamp_gte = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time after the event timestamp.</p>
    pub fn set_event_timestamp_gte(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.event_timestamp_gte = input;
        self
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time after the event timestamp.</p>
    pub fn get_event_timestamp_gte(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.event_timestamp_gte
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time prior of the event timestamp.</p>
    pub fn event_timestamp_lte(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.event_timestamp_lte = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time prior of the event timestamp.</p>
    pub fn set_event_timestamp_lte(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.event_timestamp_lte = input;
        self
    }
    /// <p>Specifies whether the action is to return data lineage node history from the time prior of the event timestamp.</p>
    pub fn get_event_timestamp_lte(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.event_timestamp_lte
    }
    /// <p>The order by which you want data lineage node history to be sorted.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order by which you want data lineage node history to be sorted.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The order by which you want data lineage node history to be sorted.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// Consumes the builder and constructs a [`ListLineageNodeHistoryInput`](crate::operation::list_lineage_node_history::ListLineageNodeHistoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_lineage_node_history::ListLineageNodeHistoryInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_lineage_node_history::ListLineageNodeHistoryInput {
            domain_identifier: self.domain_identifier,
            max_results: self.max_results,
            next_token: self.next_token,
            identifier: self.identifier,
            direction: self.direction,
            event_timestamp_gte: self.event_timestamp_gte,
            event_timestamp_lte: self.event_timestamp_lte,
            sort_order: self.sort_order,
        })
    }
}
