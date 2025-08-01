// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStreamSessionsInput {
    /// <p>Filter by the stream session status. You can specify one status in each request to retrieve only sessions that are currently in that status.</p>
    pub status: ::std::option::Option<crate::types::StreamSessionStatus>,
    /// <p>Filter by the exported files status. You can specify one status in each request to retrieve only sessions that currently have that exported files status.</p>
    /// <p>Exported files can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p><b>SUCCEEDED</b>: The exported files are successfully stored in S3 bucket.</p></li>
    /// <li>
    /// <p><b>FAILED</b>: The session ended but Amazon GameLift Streams couldn't collect and upload the to S3.</p></li>
    /// <li>
    /// <p><b>PENDING</b>: Either the stream session is still in progress, or uploading the exported files to the S3 bucket is in progress.</p></li>
    /// </ul>
    pub export_files_status: ::std::option::Option<crate::types::ExportFilesStatus>,
    /// <p>The token that marks the start of the next set of results. Use this token when you retrieve results as sequential pages. To get the first page of results, omit a token value. To get the remaining pages, provide the token returned with the previous result set.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of results to return. Use this parameter with <code>NextToken</code> to return results in sequential pages. Default value is <code>25</code>.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The unique identifier of a Amazon GameLift Streams stream group to retrieve the stream session for. You can use either the stream group ID or the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a>.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl ListStreamSessionsInput {
    /// <p>Filter by the stream session status. You can specify one status in each request to retrieve only sessions that are currently in that status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StreamSessionStatus> {
        self.status.as_ref()
    }
    /// <p>Filter by the exported files status. You can specify one status in each request to retrieve only sessions that currently have that exported files status.</p>
    /// <p>Exported files can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p><b>SUCCEEDED</b>: The exported files are successfully stored in S3 bucket.</p></li>
    /// <li>
    /// <p><b>FAILED</b>: The session ended but Amazon GameLift Streams couldn't collect and upload the to S3.</p></li>
    /// <li>
    /// <p><b>PENDING</b>: Either the stream session is still in progress, or uploading the exported files to the S3 bucket is in progress.</p></li>
    /// </ul>
    pub fn export_files_status(&self) -> ::std::option::Option<&crate::types::ExportFilesStatus> {
        self.export_files_status.as_ref()
    }
    /// <p>The token that marks the start of the next set of results. Use this token when you retrieve results as sequential pages. To get the first page of results, omit a token value. To get the remaining pages, provide the token returned with the previous result set.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The number of results to return. Use this parameter with <code>NextToken</code> to return results in sequential pages. Default value is <code>25</code>.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The unique identifier of a Amazon GameLift Streams stream group to retrieve the stream session for. You can use either the stream group ID or the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a>.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl ListStreamSessionsInput {
    /// Creates a new builder-style object to manufacture [`ListStreamSessionsInput`](crate::operation::list_stream_sessions::ListStreamSessionsInput).
    pub fn builder() -> crate::operation::list_stream_sessions::builders::ListStreamSessionsInputBuilder {
        crate::operation::list_stream_sessions::builders::ListStreamSessionsInputBuilder::default()
    }
}

/// A builder for [`ListStreamSessionsInput`](crate::operation::list_stream_sessions::ListStreamSessionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStreamSessionsInputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::StreamSessionStatus>,
    pub(crate) export_files_status: ::std::option::Option<crate::types::ExportFilesStatus>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl ListStreamSessionsInputBuilder {
    /// <p>Filter by the stream session status. You can specify one status in each request to retrieve only sessions that are currently in that status.</p>
    pub fn status(mut self, input: crate::types::StreamSessionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter by the stream session status. You can specify one status in each request to retrieve only sessions that are currently in that status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StreamSessionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Filter by the stream session status. You can specify one status in each request to retrieve only sessions that are currently in that status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StreamSessionStatus> {
        &self.status
    }
    /// <p>Filter by the exported files status. You can specify one status in each request to retrieve only sessions that currently have that exported files status.</p>
    /// <p>Exported files can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p><b>SUCCEEDED</b>: The exported files are successfully stored in S3 bucket.</p></li>
    /// <li>
    /// <p><b>FAILED</b>: The session ended but Amazon GameLift Streams couldn't collect and upload the to S3.</p></li>
    /// <li>
    /// <p><b>PENDING</b>: Either the stream session is still in progress, or uploading the exported files to the S3 bucket is in progress.</p></li>
    /// </ul>
    pub fn export_files_status(mut self, input: crate::types::ExportFilesStatus) -> Self {
        self.export_files_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter by the exported files status. You can specify one status in each request to retrieve only sessions that currently have that exported files status.</p>
    /// <p>Exported files can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p><b>SUCCEEDED</b>: The exported files are successfully stored in S3 bucket.</p></li>
    /// <li>
    /// <p><b>FAILED</b>: The session ended but Amazon GameLift Streams couldn't collect and upload the to S3.</p></li>
    /// <li>
    /// <p><b>PENDING</b>: Either the stream session is still in progress, or uploading the exported files to the S3 bucket is in progress.</p></li>
    /// </ul>
    pub fn set_export_files_status(mut self, input: ::std::option::Option<crate::types::ExportFilesStatus>) -> Self {
        self.export_files_status = input;
        self
    }
    /// <p>Filter by the exported files status. You can specify one status in each request to retrieve only sessions that currently have that exported files status.</p>
    /// <p>Exported files can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p><b>SUCCEEDED</b>: The exported files are successfully stored in S3 bucket.</p></li>
    /// <li>
    /// <p><b>FAILED</b>: The session ended but Amazon GameLift Streams couldn't collect and upload the to S3.</p></li>
    /// <li>
    /// <p><b>PENDING</b>: Either the stream session is still in progress, or uploading the exported files to the S3 bucket is in progress.</p></li>
    /// </ul>
    pub fn get_export_files_status(&self) -> &::std::option::Option<crate::types::ExportFilesStatus> {
        &self.export_files_status
    }
    /// <p>The token that marks the start of the next set of results. Use this token when you retrieve results as sequential pages. To get the first page of results, omit a token value. To get the remaining pages, provide the token returned with the previous result set.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that marks the start of the next set of results. Use this token when you retrieve results as sequential pages. To get the first page of results, omit a token value. To get the remaining pages, provide the token returned with the previous result set.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that marks the start of the next set of results. Use this token when you retrieve results as sequential pages. To get the first page of results, omit a token value. To get the remaining pages, provide the token returned with the previous result set.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The number of results to return. Use this parameter with <code>NextToken</code> to return results in sequential pages. Default value is <code>25</code>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of results to return. Use this parameter with <code>NextToken</code> to return results in sequential pages. Default value is <code>25</code>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of results to return. Use this parameter with <code>NextToken</code> to return results in sequential pages. Default value is <code>25</code>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The unique identifier of a Amazon GameLift Streams stream group to retrieve the stream session for. You can use either the stream group ID or the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a>.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of a Amazon GameLift Streams stream group to retrieve the stream session for. You can use either the stream group ID or the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a>.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique identifier of a Amazon GameLift Streams stream group to retrieve the stream session for. You can use either the stream group ID or the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a>.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`ListStreamSessionsInput`](crate::operation::list_stream_sessions::ListStreamSessionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_stream_sessions::ListStreamSessionsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_stream_sessions::ListStreamSessionsInput {
            status: self.status,
            export_files_status: self.export_files_status,
            next_token: self.next_token,
            max_results: self.max_results,
            identifier: self.identifier,
        })
    }
}
