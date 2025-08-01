// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetExecutionHistoryInput {
    /// <p>The Amazon Resource Name (ARN) of the execution.</p>
    pub execution_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Lists events in descending order of their <code>timeStamp</code>.</p>
    pub reverse_order: ::std::option::Option<bool>,
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>You can select whether execution data (input or output of a history event) is returned. The default is <code>true</code>.</p>
    pub include_execution_data: ::std::option::Option<bool>,
}
impl GetExecutionHistoryInput {
    /// <p>The Amazon Resource Name (ARN) of the execution.</p>
    pub fn execution_arn(&self) -> ::std::option::Option<&str> {
        self.execution_arn.as_deref()
    }
    /// <p>The maximum number of results that are returned per call. You can use <code>nextToken</code> to obtain further pages of results. The default is 100 and the maximum allowed page size is 1000. A value of 0 uses the default.</p>
    /// <p>This is only an upper limit. The actual number of results returned per call might be fewer than the specified maximum.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Lists events in descending order of their <code>timeStamp</code>.</p>
    pub fn reverse_order(&self) -> ::std::option::Option<bool> {
        self.reverse_order
    }
    /// <p>If <code>nextToken</code> is returned, there are more results available. The value of <code>nextToken</code> is a unique pagination token for each page. Make the call again using the returned token to retrieve the next page. Keep all other arguments unchanged. Each pagination token expires after 24 hours. Using an expired pagination token will return an <i>HTTP 400 InvalidToken</i> error.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>You can select whether execution data (input or output of a history event) is returned. The default is <code>true</code>.</p>
    pub fn include_execution_data(&self) -> ::std::option::Option<bool> {
        self.include_execution_data
    }
}
impl GetExecutionHistoryInput {
    /// Creates a new builder-style object to manufacture [`GetExecutionHistoryInput`](crate::operation::get_execution_history::GetExecutionHistoryInput).
    pub fn builder() -> crate::operation::get_execution_history::builders::GetExecutionHistoryInputBuilder {
        crate::operation::get_execution_history::builders::GetExecutionHistoryInputBuilder::default()
    }
}

/// A builder for [`GetExecutionHistoryInput`](crate::operation::get_execution_history::GetExecutionHistoryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetExecutionHistoryInputBuilder {
    pub(crate) execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) reverse_order: ::std::option::Option<bool>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) include_execution_data: ::std::option::Option<bool>,
}
impl GetExecutionHistoryInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the execution.</p>
    /// This field is required.
    pub fn execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution.</p>
    pub fn set_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the execution.</p>
    pub fn get_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_arn
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
    /// <p>Lists events in descending order of their <code>timeStamp</code>.</p>
    pub fn reverse_order(mut self, input: bool) -> Self {
        self.reverse_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lists events in descending order of their <code>timeStamp</code>.</p>
    pub fn set_reverse_order(mut self, input: ::std::option::Option<bool>) -> Self {
        self.reverse_order = input;
        self
    }
    /// <p>Lists events in descending order of their <code>timeStamp</code>.</p>
    pub fn get_reverse_order(&self) -> &::std::option::Option<bool> {
        &self.reverse_order
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
    /// <p>You can select whether execution data (input or output of a history event) is returned. The default is <code>true</code>.</p>
    pub fn include_execution_data(mut self, input: bool) -> Self {
        self.include_execution_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>You can select whether execution data (input or output of a history event) is returned. The default is <code>true</code>.</p>
    pub fn set_include_execution_data(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_execution_data = input;
        self
    }
    /// <p>You can select whether execution data (input or output of a history event) is returned. The default is <code>true</code>.</p>
    pub fn get_include_execution_data(&self) -> &::std::option::Option<bool> {
        &self.include_execution_data
    }
    /// Consumes the builder and constructs a [`GetExecutionHistoryInput`](crate::operation::get_execution_history::GetExecutionHistoryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_execution_history::GetExecutionHistoryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_execution_history::GetExecutionHistoryInput {
            execution_arn: self.execution_arn,
            max_results: self.max_results,
            reverse_order: self.reverse_order,
            next_token: self.next_token,
            include_execution_data: self.include_execution_data,
        })
    }
}
