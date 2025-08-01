// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReplicationConfigurationsInput {
    /// <p>You can retrieve the replication configuration for a specific file system by providing its file system ID. For cross-account,cross-region replication, an account can only describe the replication configuration for a file system in its own Region.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p><code>NextToken</code> is present if the response is paginated. You can use <code>NextToken</code> in a subsequent request to fetch the next page of output.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) To limit the number of objects returned in a response, you can specify the <code>MaxItems</code> parameter. The default value is 100.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeReplicationConfigurationsInput {
    /// <p>You can retrieve the replication configuration for a specific file system by providing its file system ID. For cross-account,cross-region replication, an account can only describe the replication configuration for a file system in its own Region.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p><code>NextToken</code> is present if the response is paginated. You can use <code>NextToken</code> in a subsequent request to fetch the next page of output.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>(Optional) To limit the number of objects returned in a response, you can specify the <code>MaxItems</code> parameter. The default value is 100.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeReplicationConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeReplicationConfigurationsInput`](crate::operation::describe_replication_configurations::DescribeReplicationConfigurationsInput).
    pub fn builder() -> crate::operation::describe_replication_configurations::builders::DescribeReplicationConfigurationsInputBuilder {
        crate::operation::describe_replication_configurations::builders::DescribeReplicationConfigurationsInputBuilder::default()
    }
}

/// A builder for [`DescribeReplicationConfigurationsInput`](crate::operation::describe_replication_configurations::DescribeReplicationConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReplicationConfigurationsInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeReplicationConfigurationsInputBuilder {
    /// <p>You can retrieve the replication configuration for a specific file system by providing its file system ID. For cross-account,cross-region replication, an account can only describe the replication configuration for a file system in its own Region.</p>
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>You can retrieve the replication configuration for a specific file system by providing its file system ID. For cross-account,cross-region replication, an account can only describe the replication configuration for a file system in its own Region.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>You can retrieve the replication configuration for a specific file system by providing its file system ID. For cross-account,cross-region replication, an account can only describe the replication configuration for a file system in its own Region.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// <p><code>NextToken</code> is present if the response is paginated. You can use <code>NextToken</code> in a subsequent request to fetch the next page of output.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>NextToken</code> is present if the response is paginated. You can use <code>NextToken</code> in a subsequent request to fetch the next page of output.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p><code>NextToken</code> is present if the response is paginated. You can use <code>NextToken</code> in a subsequent request to fetch the next page of output.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>(Optional) To limit the number of objects returned in a response, you can specify the <code>MaxItems</code> parameter. The default value is 100.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) To limit the number of objects returned in a response, you can specify the <code>MaxItems</code> parameter. The default value is 100.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>(Optional) To limit the number of objects returned in a response, you can specify the <code>MaxItems</code> parameter. The default value is 100.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeReplicationConfigurationsInput`](crate::operation::describe_replication_configurations::DescribeReplicationConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_replication_configurations::DescribeReplicationConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_replication_configurations::DescribeReplicationConfigurationsInput {
                file_system_id: self.file_system_id,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
