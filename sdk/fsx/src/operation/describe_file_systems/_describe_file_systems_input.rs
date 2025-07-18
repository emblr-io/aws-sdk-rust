// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request object for <code>DescribeFileSystems</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFileSystemsInput {
    /// <p>IDs of the file systems whose descriptions you want to retrieve (String).</p>
    pub file_system_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Maximum number of file systems to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Opaque pagination token returned from a previous <code>DescribeFileSystems</code> operation (String). If a token present, the operation continues the list from where the returning call left off.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFileSystemsInput {
    /// <p>IDs of the file systems whose descriptions you want to retrieve (String).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.file_system_ids.is_none()`.
    pub fn file_system_ids(&self) -> &[::std::string::String] {
        self.file_system_ids.as_deref().unwrap_or_default()
    }
    /// <p>Maximum number of file systems to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Opaque pagination token returned from a previous <code>DescribeFileSystems</code> operation (String). If a token present, the operation continues the list from where the returning call left off.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeFileSystemsInput {
    /// Creates a new builder-style object to manufacture [`DescribeFileSystemsInput`](crate::operation::describe_file_systems::DescribeFileSystemsInput).
    pub fn builder() -> crate::operation::describe_file_systems::builders::DescribeFileSystemsInputBuilder {
        crate::operation::describe_file_systems::builders::DescribeFileSystemsInputBuilder::default()
    }
}

/// A builder for [`DescribeFileSystemsInput`](crate::operation::describe_file_systems::DescribeFileSystemsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFileSystemsInputBuilder {
    pub(crate) file_system_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFileSystemsInputBuilder {
    /// Appends an item to `file_system_ids`.
    ///
    /// To override the contents of this collection use [`set_file_system_ids`](Self::set_file_system_ids).
    ///
    /// <p>IDs of the file systems whose descriptions you want to retrieve (String).</p>
    pub fn file_system_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.file_system_ids.unwrap_or_default();
        v.push(input.into());
        self.file_system_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>IDs of the file systems whose descriptions you want to retrieve (String).</p>
    pub fn set_file_system_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.file_system_ids = input;
        self
    }
    /// <p>IDs of the file systems whose descriptions you want to retrieve (String).</p>
    pub fn get_file_system_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.file_system_ids
    }
    /// <p>Maximum number of file systems to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of file systems to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of file systems to return in the response (integer). This parameter value must be greater than 0. The number of items that Amazon FSx returns is the minimum of the <code>MaxResults</code> parameter specified in the request and the service's internal maximum number of items per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Opaque pagination token returned from a previous <code>DescribeFileSystems</code> operation (String). If a token present, the operation continues the list from where the returning call left off.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Opaque pagination token returned from a previous <code>DescribeFileSystems</code> operation (String). If a token present, the operation continues the list from where the returning call left off.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Opaque pagination token returned from a previous <code>DescribeFileSystems</code> operation (String). If a token present, the operation continues the list from where the returning call left off.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeFileSystemsInput`](crate::operation::describe_file_systems::DescribeFileSystemsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_file_systems::DescribeFileSystemsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_file_systems::DescribeFileSystemsInput {
            file_system_ids: self.file_system_ids,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
