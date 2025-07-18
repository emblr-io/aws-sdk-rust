// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFileTransferResultsOutput {
    /// <p>Returns the details for the files transferred in the transfer identified by the <code>TransferId</code> and <code>ConnectorId</code> specified.</p>
    /// <ul>
    /// <li>
    /// <p><code>FilePath</code>: the filename and path to where the file was sent to or retrieved from.</p></li>
    /// <li>
    /// <p><code>StatusCode</code>: current status for the transfer. The status returned is one of the following values:<code>QUEUED</code>, <code>IN_PROGRESS</code>, <code>COMPLETED</code>, or <code>FAILED</code></p></li>
    /// <li>
    /// <p><code>FailureCode</code>: for transfers that fail, this parameter contains a code indicating the reason. For example, <code>RETRIEVE_FILE_NOT_FOUND</code></p></li>
    /// <li>
    /// <p><code>FailureMessage</code>: for transfers that fail, this parameter describes the reason for the failure.</p></li>
    /// </ul>
    pub file_transfer_results: ::std::vec::Vec<crate::types::ConnectorFileTransferResult>,
    /// <p>Returns a token that you can use to call <code>ListFileTransferResults</code> again and receive additional results, if there are any (against the same <code>TransferId</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFileTransferResultsOutput {
    /// <p>Returns the details for the files transferred in the transfer identified by the <code>TransferId</code> and <code>ConnectorId</code> specified.</p>
    /// <ul>
    /// <li>
    /// <p><code>FilePath</code>: the filename and path to where the file was sent to or retrieved from.</p></li>
    /// <li>
    /// <p><code>StatusCode</code>: current status for the transfer. The status returned is one of the following values:<code>QUEUED</code>, <code>IN_PROGRESS</code>, <code>COMPLETED</code>, or <code>FAILED</code></p></li>
    /// <li>
    /// <p><code>FailureCode</code>: for transfers that fail, this parameter contains a code indicating the reason. For example, <code>RETRIEVE_FILE_NOT_FOUND</code></p></li>
    /// <li>
    /// <p><code>FailureMessage</code>: for transfers that fail, this parameter describes the reason for the failure.</p></li>
    /// </ul>
    pub fn file_transfer_results(&self) -> &[crate::types::ConnectorFileTransferResult] {
        use std::ops::Deref;
        self.file_transfer_results.deref()
    }
    /// <p>Returns a token that you can use to call <code>ListFileTransferResults</code> again and receive additional results, if there are any (against the same <code>TransferId</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFileTransferResultsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFileTransferResultsOutput {
    /// Creates a new builder-style object to manufacture [`ListFileTransferResultsOutput`](crate::operation::list_file_transfer_results::ListFileTransferResultsOutput).
    pub fn builder() -> crate::operation::list_file_transfer_results::builders::ListFileTransferResultsOutputBuilder {
        crate::operation::list_file_transfer_results::builders::ListFileTransferResultsOutputBuilder::default()
    }
}

/// A builder for [`ListFileTransferResultsOutput`](crate::operation::list_file_transfer_results::ListFileTransferResultsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFileTransferResultsOutputBuilder {
    pub(crate) file_transfer_results: ::std::option::Option<::std::vec::Vec<crate::types::ConnectorFileTransferResult>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFileTransferResultsOutputBuilder {
    /// Appends an item to `file_transfer_results`.
    ///
    /// To override the contents of this collection use [`set_file_transfer_results`](Self::set_file_transfer_results).
    ///
    /// <p>Returns the details for the files transferred in the transfer identified by the <code>TransferId</code> and <code>ConnectorId</code> specified.</p>
    /// <ul>
    /// <li>
    /// <p><code>FilePath</code>: the filename and path to where the file was sent to or retrieved from.</p></li>
    /// <li>
    /// <p><code>StatusCode</code>: current status for the transfer. The status returned is one of the following values:<code>QUEUED</code>, <code>IN_PROGRESS</code>, <code>COMPLETED</code>, or <code>FAILED</code></p></li>
    /// <li>
    /// <p><code>FailureCode</code>: for transfers that fail, this parameter contains a code indicating the reason. For example, <code>RETRIEVE_FILE_NOT_FOUND</code></p></li>
    /// <li>
    /// <p><code>FailureMessage</code>: for transfers that fail, this parameter describes the reason for the failure.</p></li>
    /// </ul>
    pub fn file_transfer_results(mut self, input: crate::types::ConnectorFileTransferResult) -> Self {
        let mut v = self.file_transfer_results.unwrap_or_default();
        v.push(input);
        self.file_transfer_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the details for the files transferred in the transfer identified by the <code>TransferId</code> and <code>ConnectorId</code> specified.</p>
    /// <ul>
    /// <li>
    /// <p><code>FilePath</code>: the filename and path to where the file was sent to or retrieved from.</p></li>
    /// <li>
    /// <p><code>StatusCode</code>: current status for the transfer. The status returned is one of the following values:<code>QUEUED</code>, <code>IN_PROGRESS</code>, <code>COMPLETED</code>, or <code>FAILED</code></p></li>
    /// <li>
    /// <p><code>FailureCode</code>: for transfers that fail, this parameter contains a code indicating the reason. For example, <code>RETRIEVE_FILE_NOT_FOUND</code></p></li>
    /// <li>
    /// <p><code>FailureMessage</code>: for transfers that fail, this parameter describes the reason for the failure.</p></li>
    /// </ul>
    pub fn set_file_transfer_results(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConnectorFileTransferResult>>) -> Self {
        self.file_transfer_results = input;
        self
    }
    /// <p>Returns the details for the files transferred in the transfer identified by the <code>TransferId</code> and <code>ConnectorId</code> specified.</p>
    /// <ul>
    /// <li>
    /// <p><code>FilePath</code>: the filename and path to where the file was sent to or retrieved from.</p></li>
    /// <li>
    /// <p><code>StatusCode</code>: current status for the transfer. The status returned is one of the following values:<code>QUEUED</code>, <code>IN_PROGRESS</code>, <code>COMPLETED</code>, or <code>FAILED</code></p></li>
    /// <li>
    /// <p><code>FailureCode</code>: for transfers that fail, this parameter contains a code indicating the reason. For example, <code>RETRIEVE_FILE_NOT_FOUND</code></p></li>
    /// <li>
    /// <p><code>FailureMessage</code>: for transfers that fail, this parameter describes the reason for the failure.</p></li>
    /// </ul>
    pub fn get_file_transfer_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConnectorFileTransferResult>> {
        &self.file_transfer_results
    }
    /// <p>Returns a token that you can use to call <code>ListFileTransferResults</code> again and receive additional results, if there are any (against the same <code>TransferId</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns a token that you can use to call <code>ListFileTransferResults</code> again and receive additional results, if there are any (against the same <code>TransferId</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Returns a token that you can use to call <code>ListFileTransferResults</code> again and receive additional results, if there are any (against the same <code>TransferId</code>.</p>
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
    /// Consumes the builder and constructs a [`ListFileTransferResultsOutput`](crate::operation::list_file_transfer_results::ListFileTransferResultsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`file_transfer_results`](crate::operation::list_file_transfer_results::builders::ListFileTransferResultsOutputBuilder::file_transfer_results)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_file_transfer_results::ListFileTransferResultsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_file_transfer_results::ListFileTransferResultsOutput {
            file_transfer_results: self.file_transfer_results.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "file_transfer_results",
                    "file_transfer_results was not specified but it is required when building ListFileTransferResultsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
