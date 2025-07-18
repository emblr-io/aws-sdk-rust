// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStackResourceDriftsInput {
    /// <p>The name of the stack for which you want drift information.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The resource drift status values to use as filters for the resource drift results returned.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETED</code>: The resource differs from its expected template configuration in that the resource has been deleted.</p></li>
    /// <li>
    /// <p><code>MODIFIED</code>: One or more resource properties differ from their expected template values.</p></li>
    /// <li>
    /// <p><code>IN_SYNC</code>: The resource's actual configuration matches its expected template configuration.</p></li>
    /// <li>
    /// <p><code>NOT_CHECKED</code>: CloudFormation doesn't currently return this value.</p></li>
    /// <li>
    /// <p><code>UNKNOWN</code>: CloudFormation could not run drift detection for the resource.</p></li>
    /// </ul>
    pub stack_resource_drift_status_filters: ::std::option::Option<::std::vec::Vec<crate::types::StackResourceDriftStatus>>,
    /// <p>A string that identifies the next page of stack resource drift results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned with a single call. If the number of available results exceeds this maximum, the response includes a <code>NextToken</code> value that you can assign to the <code>NextToken</code> request parameter to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeStackResourceDriftsInput {
    /// <p>The name of the stack for which you want drift information.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>The resource drift status values to use as filters for the resource drift results returned.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETED</code>: The resource differs from its expected template configuration in that the resource has been deleted.</p></li>
    /// <li>
    /// <p><code>MODIFIED</code>: One or more resource properties differ from their expected template values.</p></li>
    /// <li>
    /// <p><code>IN_SYNC</code>: The resource's actual configuration matches its expected template configuration.</p></li>
    /// <li>
    /// <p><code>NOT_CHECKED</code>: CloudFormation doesn't currently return this value.</p></li>
    /// <li>
    /// <p><code>UNKNOWN</code>: CloudFormation could not run drift detection for the resource.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stack_resource_drift_status_filters.is_none()`.
    pub fn stack_resource_drift_status_filters(&self) -> &[crate::types::StackResourceDriftStatus] {
        self.stack_resource_drift_status_filters.as_deref().unwrap_or_default()
    }
    /// <p>A string that identifies the next page of stack resource drift results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to be returned with a single call. If the number of available results exceeds this maximum, the response includes a <code>NextToken</code> value that you can assign to the <code>NextToken</code> request parameter to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeStackResourceDriftsInput {
    /// Creates a new builder-style object to manufacture [`DescribeStackResourceDriftsInput`](crate::operation::describe_stack_resource_drifts::DescribeStackResourceDriftsInput).
    pub fn builder() -> crate::operation::describe_stack_resource_drifts::builders::DescribeStackResourceDriftsInputBuilder {
        crate::operation::describe_stack_resource_drifts::builders::DescribeStackResourceDriftsInputBuilder::default()
    }
}

/// A builder for [`DescribeStackResourceDriftsInput`](crate::operation::describe_stack_resource_drifts::DescribeStackResourceDriftsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStackResourceDriftsInputBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) stack_resource_drift_status_filters: ::std::option::Option<::std::vec::Vec<crate::types::StackResourceDriftStatus>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeStackResourceDriftsInputBuilder {
    /// <p>The name of the stack for which you want drift information.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack for which you want drift information.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name of the stack for which you want drift information.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// Appends an item to `stack_resource_drift_status_filters`.
    ///
    /// To override the contents of this collection use [`set_stack_resource_drift_status_filters`](Self::set_stack_resource_drift_status_filters).
    ///
    /// <p>The resource drift status values to use as filters for the resource drift results returned.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETED</code>: The resource differs from its expected template configuration in that the resource has been deleted.</p></li>
    /// <li>
    /// <p><code>MODIFIED</code>: One or more resource properties differ from their expected template values.</p></li>
    /// <li>
    /// <p><code>IN_SYNC</code>: The resource's actual configuration matches its expected template configuration.</p></li>
    /// <li>
    /// <p><code>NOT_CHECKED</code>: CloudFormation doesn't currently return this value.</p></li>
    /// <li>
    /// <p><code>UNKNOWN</code>: CloudFormation could not run drift detection for the resource.</p></li>
    /// </ul>
    pub fn stack_resource_drift_status_filters(mut self, input: crate::types::StackResourceDriftStatus) -> Self {
        let mut v = self.stack_resource_drift_status_filters.unwrap_or_default();
        v.push(input);
        self.stack_resource_drift_status_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The resource drift status values to use as filters for the resource drift results returned.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETED</code>: The resource differs from its expected template configuration in that the resource has been deleted.</p></li>
    /// <li>
    /// <p><code>MODIFIED</code>: One or more resource properties differ from their expected template values.</p></li>
    /// <li>
    /// <p><code>IN_SYNC</code>: The resource's actual configuration matches its expected template configuration.</p></li>
    /// <li>
    /// <p><code>NOT_CHECKED</code>: CloudFormation doesn't currently return this value.</p></li>
    /// <li>
    /// <p><code>UNKNOWN</code>: CloudFormation could not run drift detection for the resource.</p></li>
    /// </ul>
    pub fn set_stack_resource_drift_status_filters(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::StackResourceDriftStatus>>,
    ) -> Self {
        self.stack_resource_drift_status_filters = input;
        self
    }
    /// <p>The resource drift status values to use as filters for the resource drift results returned.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETED</code>: The resource differs from its expected template configuration in that the resource has been deleted.</p></li>
    /// <li>
    /// <p><code>MODIFIED</code>: One or more resource properties differ from their expected template values.</p></li>
    /// <li>
    /// <p><code>IN_SYNC</code>: The resource's actual configuration matches its expected template configuration.</p></li>
    /// <li>
    /// <p><code>NOT_CHECKED</code>: CloudFormation doesn't currently return this value.</p></li>
    /// <li>
    /// <p><code>UNKNOWN</code>: CloudFormation could not run drift detection for the resource.</p></li>
    /// </ul>
    pub fn get_stack_resource_drift_status_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StackResourceDriftStatus>> {
        &self.stack_resource_drift_status_filters
    }
    /// <p>A string that identifies the next page of stack resource drift results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that identifies the next page of stack resource drift results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A string that identifies the next page of stack resource drift results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to be returned with a single call. If the number of available results exceeds this maximum, the response includes a <code>NextToken</code> value that you can assign to the <code>NextToken</code> request parameter to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned with a single call. If the number of available results exceeds this maximum, the response includes a <code>NextToken</code> value that you can assign to the <code>NextToken</code> request parameter to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned with a single call. If the number of available results exceeds this maximum, the response includes a <code>NextToken</code> value that you can assign to the <code>NextToken</code> request parameter to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeStackResourceDriftsInput`](crate::operation::describe_stack_resource_drifts::DescribeStackResourceDriftsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_stack_resource_drifts::DescribeStackResourceDriftsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_stack_resource_drifts::DescribeStackResourceDriftsInput {
            stack_name: self.stack_name,
            stack_resource_drift_status_filters: self.stack_resource_drift_status_filters,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
