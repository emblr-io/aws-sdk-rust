// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListHumanLoopsInput {
    /// <p>(Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>(Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of a flow definition.</p>
    pub flow_definition_arn: ::std::option::Option<::std::string::String>,
    /// <p>Optional. The order for displaying results. Valid values: <code>Ascending</code> and <code>Descending</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>A token to display the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The total number of items to return. If the total number of available items is more than the value specified in <code>MaxResults</code>, then a <code>NextToken</code> is returned in the output. You can use this token to display the next page of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListHumanLoopsInput {
    /// <p>(Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn creation_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_after.as_ref()
    }
    /// <p>(Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn creation_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_before.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of a flow definition.</p>
    pub fn flow_definition_arn(&self) -> ::std::option::Option<&str> {
        self.flow_definition_arn.as_deref()
    }
    /// <p>Optional. The order for displaying results. Valid values: <code>Ascending</code> and <code>Descending</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>A token to display the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The total number of items to return. If the total number of available items is more than the value specified in <code>MaxResults</code>, then a <code>NextToken</code> is returned in the output. You can use this token to display the next page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListHumanLoopsInput {
    /// Creates a new builder-style object to manufacture [`ListHumanLoopsInput`](crate::operation::list_human_loops::ListHumanLoopsInput).
    pub fn builder() -> crate::operation::list_human_loops::builders::ListHumanLoopsInputBuilder {
        crate::operation::list_human_loops::builders::ListHumanLoopsInputBuilder::default()
    }
}

/// A builder for [`ListHumanLoopsInput`](crate::operation::list_human_loops::ListHumanLoopsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListHumanLoopsInputBuilder {
    pub(crate) creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) flow_definition_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListHumanLoopsInputBuilder {
    /// <p>(Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn creation_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn set_creation_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_after = input;
        self
    }
    /// <p>(Optional) The timestamp of the date when you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn get_creation_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_after
    }
    /// <p>(Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn creation_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn set_creation_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_before = input;
        self
    }
    /// <p>(Optional) The timestamp of the date before which you want the human loops to begin in ISO 8601 format. For example, <code>2020-02-24</code>.</p>
    pub fn get_creation_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_before
    }
    /// <p>The Amazon Resource Name (ARN) of a flow definition.</p>
    /// This field is required.
    pub fn flow_definition_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.flow_definition_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a flow definition.</p>
    pub fn set_flow_definition_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.flow_definition_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a flow definition.</p>
    pub fn get_flow_definition_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.flow_definition_arn
    }
    /// <p>Optional. The order for displaying results. Valid values: <code>Ascending</code> and <code>Descending</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional. The order for displaying results. Valid values: <code>Ascending</code> and <code>Descending</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>Optional. The order for displaying results. Valid values: <code>Ascending</code> and <code>Descending</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>A token to display the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to display the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to display the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The total number of items to return. If the total number of available items is more than the value specified in <code>MaxResults</code>, then a <code>NextToken</code> is returned in the output. You can use this token to display the next page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of items to return. If the total number of available items is more than the value specified in <code>MaxResults</code>, then a <code>NextToken</code> is returned in the output. You can use this token to display the next page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The total number of items to return. If the total number of available items is more than the value specified in <code>MaxResults</code>, then a <code>NextToken</code> is returned in the output. You can use this token to display the next page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListHumanLoopsInput`](crate::operation::list_human_loops::ListHumanLoopsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_human_loops::ListHumanLoopsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_human_loops::ListHumanLoopsInput {
            creation_time_after: self.creation_time_after,
            creation_time_before: self.creation_time_before,
            flow_definition_arn: self.flow_definition_arn,
            sort_order: self.sort_order,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
