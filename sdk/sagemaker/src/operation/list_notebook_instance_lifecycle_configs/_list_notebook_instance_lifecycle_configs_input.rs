// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNotebookInstanceLifecycleConfigsInput {
    /// <p>If the result of a <code>ListNotebookInstanceLifecycleConfigs</code> request was truncated, the response includes a <code>NextToken</code>. To get the next set of lifecycle configurations, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of lifecycle configurations to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Sorts the list of results. The default is <code>CreationTime</code>.</p>
    pub sort_by: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortKey>,
    /// <p>The sort order for results.</p>
    pub sort_order: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortOrder>,
    /// <p>A string in the lifecycle configuration name. This filter returns only lifecycle configurations whose name contains the specified string.</p>
    pub name_contains: ::std::option::Option<::std::string::String>,
    /// <p>A filter that returns only lifecycle configurations that were created before the specified time (timestamp).</p>
    pub creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only lifecycle configurations that were created after the specified time (timestamp).</p>
    pub creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only lifecycle configurations that were modified before the specified time (timestamp).</p>
    pub last_modified_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only lifecycle configurations that were modified after the specified time (timestamp).</p>
    pub last_modified_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ListNotebookInstanceLifecycleConfigsInput {
    /// <p>If the result of a <code>ListNotebookInstanceLifecycleConfigs</code> request was truncated, the response includes a <code>NextToken</code>. To get the next set of lifecycle configurations, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of lifecycle configurations to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Sorts the list of results. The default is <code>CreationTime</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::NotebookInstanceLifecycleConfigSortKey> {
        self.sort_by.as_ref()
    }
    /// <p>The sort order for results.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::NotebookInstanceLifecycleConfigSortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>A string in the lifecycle configuration name. This filter returns only lifecycle configurations whose name contains the specified string.</p>
    pub fn name_contains(&self) -> ::std::option::Option<&str> {
        self.name_contains.as_deref()
    }
    /// <p>A filter that returns only lifecycle configurations that were created before the specified time (timestamp).</p>
    pub fn creation_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_before.as_ref()
    }
    /// <p>A filter that returns only lifecycle configurations that were created after the specified time (timestamp).</p>
    pub fn creation_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_after.as_ref()
    }
    /// <p>A filter that returns only lifecycle configurations that were modified before the specified time (timestamp).</p>
    pub fn last_modified_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time_before.as_ref()
    }
    /// <p>A filter that returns only lifecycle configurations that were modified after the specified time (timestamp).</p>
    pub fn last_modified_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time_after.as_ref()
    }
}
impl ListNotebookInstanceLifecycleConfigsInput {
    /// Creates a new builder-style object to manufacture [`ListNotebookInstanceLifecycleConfigsInput`](crate::operation::list_notebook_instance_lifecycle_configs::ListNotebookInstanceLifecycleConfigsInput).
    pub fn builder() -> crate::operation::list_notebook_instance_lifecycle_configs::builders::ListNotebookInstanceLifecycleConfigsInputBuilder {
        crate::operation::list_notebook_instance_lifecycle_configs::builders::ListNotebookInstanceLifecycleConfigsInputBuilder::default()
    }
}

/// A builder for [`ListNotebookInstanceLifecycleConfigsInput`](crate::operation::list_notebook_instance_lifecycle_configs::ListNotebookInstanceLifecycleConfigsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNotebookInstanceLifecycleConfigsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) sort_by: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortKey>,
    pub(crate) sort_order: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortOrder>,
    pub(crate) name_contains: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ListNotebookInstanceLifecycleConfigsInputBuilder {
    /// <p>If the result of a <code>ListNotebookInstanceLifecycleConfigs</code> request was truncated, the response includes a <code>NextToken</code>. To get the next set of lifecycle configurations, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of a <code>ListNotebookInstanceLifecycleConfigs</code> request was truncated, the response includes a <code>NextToken</code>. To get the next set of lifecycle configurations, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the result of a <code>ListNotebookInstanceLifecycleConfigs</code> request was truncated, the response includes a <code>NextToken</code>. To get the next set of lifecycle configurations, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of lifecycle configurations to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of lifecycle configurations to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of lifecycle configurations to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Sorts the list of results. The default is <code>CreationTime</code>.</p>
    pub fn sort_by(mut self, input: crate::types::NotebookInstanceLifecycleConfigSortKey) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sorts the list of results. The default is <code>CreationTime</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortKey>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Sorts the list of results. The default is <code>CreationTime</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortKey> {
        &self.sort_by
    }
    /// <p>The sort order for results.</p>
    pub fn sort_order(mut self, input: crate::types::NotebookInstanceLifecycleConfigSortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order for results.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sort order for results.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::NotebookInstanceLifecycleConfigSortOrder> {
        &self.sort_order
    }
    /// <p>A string in the lifecycle configuration name. This filter returns only lifecycle configurations whose name contains the specified string.</p>
    pub fn name_contains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name_contains = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string in the lifecycle configuration name. This filter returns only lifecycle configurations whose name contains the specified string.</p>
    pub fn set_name_contains(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name_contains = input;
        self
    }
    /// <p>A string in the lifecycle configuration name. This filter returns only lifecycle configurations whose name contains the specified string.</p>
    pub fn get_name_contains(&self) -> &::std::option::Option<::std::string::String> {
        &self.name_contains
    }
    /// <p>A filter that returns only lifecycle configurations that were created before the specified time (timestamp).</p>
    pub fn creation_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were created before the specified time (timestamp).</p>
    pub fn set_creation_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_before = input;
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were created before the specified time (timestamp).</p>
    pub fn get_creation_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_before
    }
    /// <p>A filter that returns only lifecycle configurations that were created after the specified time (timestamp).</p>
    pub fn creation_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were created after the specified time (timestamp).</p>
    pub fn set_creation_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_after = input;
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were created after the specified time (timestamp).</p>
    pub fn get_creation_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_after
    }
    /// <p>A filter that returns only lifecycle configurations that were modified before the specified time (timestamp).</p>
    pub fn last_modified_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were modified before the specified time (timestamp).</p>
    pub fn set_last_modified_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time_before = input;
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were modified before the specified time (timestamp).</p>
    pub fn get_last_modified_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time_before
    }
    /// <p>A filter that returns only lifecycle configurations that were modified after the specified time (timestamp).</p>
    pub fn last_modified_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were modified after the specified time (timestamp).</p>
    pub fn set_last_modified_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time_after = input;
        self
    }
    /// <p>A filter that returns only lifecycle configurations that were modified after the specified time (timestamp).</p>
    pub fn get_last_modified_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time_after
    }
    /// Consumes the builder and constructs a [`ListNotebookInstanceLifecycleConfigsInput`](crate::operation::list_notebook_instance_lifecycle_configs::ListNotebookInstanceLifecycleConfigsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_notebook_instance_lifecycle_configs::ListNotebookInstanceLifecycleConfigsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_notebook_instance_lifecycle_configs::ListNotebookInstanceLifecycleConfigsInput {
                next_token: self.next_token,
                max_results: self.max_results,
                sort_by: self.sort_by,
                sort_order: self.sort_order,
                name_contains: self.name_contains,
                creation_time_before: self.creation_time_before,
                creation_time_after: self.creation_time_after,
                last_modified_time_before: self.last_modified_time_before,
                last_modified_time_after: self.last_modified_time_after,
            },
        )
    }
}
