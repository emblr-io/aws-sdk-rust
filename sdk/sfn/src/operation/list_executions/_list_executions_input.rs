// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListExecutionsInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine whose executions is listed.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    /// <p>You can also return a list of executions associated with a specific <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-alias.html">alias</a> or <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-version.html">version</a>, by specifying an alias ARN or a version ARN in the <code>stateMachineArn</code> parameter.</p>
    pub state_machine_arn: ::std::option::Option<::std::string::String>,
    /// <p>If specified, only list the executions whose current execution status matches the given filter.</p>
    pub status_filter: ::std::option::Option<crate::types::ExecutionStatus>,
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Map Run that started the child workflow executions. If the <code>mapRunArn</code> field is specified, a list of all of the child workflow executions started by a Map Run is returned. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-examine-map-run.html">Examining Map Run</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    pub map_run_arn: ::std::option::Option<::std::string::String>,
    /// <p>Sets a filter to list executions based on whether or not they have been redriven.</p>
    /// <p>For a Distributed Map, <code>redriveFilter</code> sets a filter to list child workflow executions based on whether or not they have been redriven.</p>
    /// <p>If you do not provide a <code>redriveFilter</code>, Step Functions returns a list of both redriven and non-redriven executions.</p>
    /// <p>If you provide a state machine ARN in <code>redriveFilter</code>, the API returns a validation exception.</p>
    pub redrive_filter: ::std::option::Option<crate::types::ExecutionRedriveFilter>,
}
impl ListExecutionsInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine whose executions is listed.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    /// <p>You can also return a list of executions associated with a specific <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-alias.html">alias</a> or <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-version.html">version</a>, by specifying an alias ARN or a version ARN in the <code>stateMachineArn</code> parameter.</p>
    pub fn state_machine_arn(&self) -> ::std::option::Option<&str> {
        self.state_machine_arn.as_deref()
    }
    /// <p>If specified, only list the executions whose current execution status matches the given filter.</p>
    pub fn status_filter(&self) -> ::std::option::Option<&crate::types::ExecutionStatus> {
        self.status_filter.as_ref()
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Map Run that started the child workflow executions. If the <code>mapRunArn</code> field is specified, a list of all of the child workflow executions started by a Map Run is returned. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-examine-map-run.html">Examining Map Run</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    pub fn map_run_arn(&self) -> ::std::option::Option<&str> {
        self.map_run_arn.as_deref()
    }
    /// <p>Sets a filter to list executions based on whether or not they have been redriven.</p>
    /// <p>For a Distributed Map, <code>redriveFilter</code> sets a filter to list child workflow executions based on whether or not they have been redriven.</p>
    /// <p>If you do not provide a <code>redriveFilter</code>, Step Functions returns a list of both redriven and non-redriven executions.</p>
    /// <p>If you provide a state machine ARN in <code>redriveFilter</code>, the API returns a validation exception.</p>
    pub fn redrive_filter(&self) -> ::std::option::Option<&crate::types::ExecutionRedriveFilter> {
        self.redrive_filter.as_ref()
    }
}
impl ListExecutionsInput {
    /// Creates a new builder-style object to manufacture [`ListExecutionsInput`](crate::operation::list_executions::ListExecutionsInput).
    pub fn builder() -> crate::operation::list_executions::builders::ListExecutionsInputBuilder {
        crate::operation::list_executions::builders::ListExecutionsInputBuilder::default()
    }
}

/// A builder for [`ListExecutionsInput`](crate::operation::list_executions::ListExecutionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListExecutionsInputBuilder {
    pub(crate) state_machine_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status_filter: ::std::option::Option<crate::types::ExecutionStatus>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) map_run_arn: ::std::option::Option<::std::string::String>,
    pub(crate) redrive_filter: ::std::option::Option<crate::types::ExecutionRedriveFilter>,
}
impl ListExecutionsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the state machine whose executions is listed.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    /// <p>You can also return a list of executions associated with a specific <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-alias.html">alias</a> or <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-version.html">version</a>, by specifying an alias ARN or a version ARN in the <code>stateMachineArn</code> parameter.</p>
    pub fn state_machine_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_machine_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine whose executions is listed.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    /// <p>You can also return a list of executions associated with a specific <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-alias.html">alias</a> or <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-version.html">version</a>, by specifying an alias ARN or a version ARN in the <code>stateMachineArn</code> parameter.</p>
    pub fn set_state_machine_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_machine_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine whose executions is listed.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    /// <p>You can also return a list of executions associated with a specific <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-alias.html">alias</a> or <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-state-machine-version.html">version</a>, by specifying an alias ARN or a version ARN in the <code>stateMachineArn</code> parameter.</p>
    pub fn get_state_machine_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_machine_arn
    }
    /// <p>If specified, only list the executions whose current execution status matches the given filter.</p>
    pub fn status_filter(mut self, input: crate::types::ExecutionStatus) -> Self {
        self.status_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>If specified, only list the executions whose current execution status matches the given filter.</p>
    pub fn set_status_filter(mut self, input: ::std::option::Option<crate::types::ExecutionStatus>) -> Self {
        self.status_filter = input;
        self
    }
    /// <p>If specified, only list the executions whose current execution status matches the given filter.</p>
    pub fn get_status_filter(&self) -> &::std::option::Option<crate::types::ExecutionStatus> {
        &self.status_filter
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The Amazon Resource Name (ARN) of the Map Run that started the child workflow executions. If the <code>mapRunArn</code> field is specified, a list of all of the child workflow executions started by a Map Run is returned. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-examine-map-run.html">Examining Map Run</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    pub fn map_run_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.map_run_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Map Run that started the child workflow executions. If the <code>mapRunArn</code> field is specified, a list of all of the child workflow executions started by a Map Run is returned. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-examine-map-run.html">Examining Map Run</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    pub fn set_map_run_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.map_run_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Map Run that started the child workflow executions. If the <code>mapRunArn</code> field is specified, a list of all of the child workflow executions started by a Map Run is returned. For more information, see <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-examine-map-run.html">Examining Map Run</a> in the <i>Step Functions Developer Guide</i>.</p>
    /// <p>You can specify either a <code>mapRunArn</code> or a <code>stateMachineArn</code>, but not both.</p>
    pub fn get_map_run_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.map_run_arn
    }
    /// <p>Sets a filter to list executions based on whether or not they have been redriven.</p>
    /// <p>For a Distributed Map, <code>redriveFilter</code> sets a filter to list child workflow executions based on whether or not they have been redriven.</p>
    /// <p>If you do not provide a <code>redriveFilter</code>, Step Functions returns a list of both redriven and non-redriven executions.</p>
    /// <p>If you provide a state machine ARN in <code>redriveFilter</code>, the API returns a validation exception.</p>
    pub fn redrive_filter(mut self, input: crate::types::ExecutionRedriveFilter) -> Self {
        self.redrive_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets a filter to list executions based on whether or not they have been redriven.</p>
    /// <p>For a Distributed Map, <code>redriveFilter</code> sets a filter to list child workflow executions based on whether or not they have been redriven.</p>
    /// <p>If you do not provide a <code>redriveFilter</code>, Step Functions returns a list of both redriven and non-redriven executions.</p>
    /// <p>If you provide a state machine ARN in <code>redriveFilter</code>, the API returns a validation exception.</p>
    pub fn set_redrive_filter(mut self, input: ::std::option::Option<crate::types::ExecutionRedriveFilter>) -> Self {
        self.redrive_filter = input;
        self
    }
    /// <p>Sets a filter to list executions based on whether or not they have been redriven.</p>
    /// <p>For a Distributed Map, <code>redriveFilter</code> sets a filter to list child workflow executions based on whether or not they have been redriven.</p>
    /// <p>If you do not provide a <code>redriveFilter</code>, Step Functions returns a list of both redriven and non-redriven executions.</p>
    /// <p>If you provide a state machine ARN in <code>redriveFilter</code>, the API returns a validation exception.</p>
    pub fn get_redrive_filter(&self) -> &::std::option::Option<crate::types::ExecutionRedriveFilter> {
        &self.redrive_filter
    }
    /// Consumes the builder and constructs a [`ListExecutionsInput`](crate::operation::list_executions::ListExecutionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_executions::ListExecutionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_executions::ListExecutionsInput {
            state_machine_arn: self.state_machine_arn,
            status_filter: self.status_filter,
            max_results: self.max_results,
            next_token: self.next_token,
            map_run_arn: self.map_run_arn,
            redrive_filter: self.redrive_filter,
        })
    }
}
