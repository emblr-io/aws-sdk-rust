// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeChangeSetOutput {
    /// <p>Required. The unique identifier for the change set referenced in this request.</p>
    pub change_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN associated with the unique identifier for the change set referenced in this request.</p>
    pub change_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The optional name provided in the <code>StartChangeSet</code> request. If you do not provide a name, one is set by default.</p>
    pub change_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The optional intent provided in the <code>StartChangeSet</code> request. If you do not provide an intent, <code>APPLY</code> is set by default.</p>
    pub intent: ::std::option::Option<crate::types::Intent>,
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request started.</p>
    pub start_time: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request transitioned to a terminal state. The change cannot transition to a different state. Null if the request is not in a terminal state.</p>
    pub end_time: ::std::option::Option<::std::string::String>,
    /// <p>The status of the change request.</p>
    pub status: ::std::option::Option<crate::types::ChangeStatus>,
    /// <p>Returned if the change set is in <code>FAILED</code> status. Can be either <code>CLIENT_ERROR</code>, which means that there are issues with the request (see the <code>ErrorDetailList</code>), or <code>SERVER_FAULT</code>, which means that there is a problem in the system, and you should retry your request.</p>
    pub failure_code: ::std::option::Option<crate::types::FailureCode>,
    /// <p>Returned if there is a failure on the change set, but that failure is not related to any of the changes in the request.</p>
    pub failure_description: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>ChangeSummary</code> objects.</p>
    pub change_set: ::std::option::Option<::std::vec::Vec<crate::types::ChangeSummary>>,
    _request_id: Option<String>,
}
impl DescribeChangeSetOutput {
    /// <p>Required. The unique identifier for the change set referenced in this request.</p>
    pub fn change_set_id(&self) -> ::std::option::Option<&str> {
        self.change_set_id.as_deref()
    }
    /// <p>The ARN associated with the unique identifier for the change set referenced in this request.</p>
    pub fn change_set_arn(&self) -> ::std::option::Option<&str> {
        self.change_set_arn.as_deref()
    }
    /// <p>The optional name provided in the <code>StartChangeSet</code> request. If you do not provide a name, one is set by default.</p>
    pub fn change_set_name(&self) -> ::std::option::Option<&str> {
        self.change_set_name.as_deref()
    }
    /// <p>The optional intent provided in the <code>StartChangeSet</code> request. If you do not provide an intent, <code>APPLY</code> is set by default.</p>
    pub fn intent(&self) -> ::std::option::Option<&crate::types::Intent> {
        self.intent.as_ref()
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&str> {
        self.start_time.as_deref()
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request transitioned to a terminal state. The change cannot transition to a different state. Null if the request is not in a terminal state.</p>
    pub fn end_time(&self) -> ::std::option::Option<&str> {
        self.end_time.as_deref()
    }
    /// <p>The status of the change request.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ChangeStatus> {
        self.status.as_ref()
    }
    /// <p>Returned if the change set is in <code>FAILED</code> status. Can be either <code>CLIENT_ERROR</code>, which means that there are issues with the request (see the <code>ErrorDetailList</code>), or <code>SERVER_FAULT</code>, which means that there is a problem in the system, and you should retry your request.</p>
    pub fn failure_code(&self) -> ::std::option::Option<&crate::types::FailureCode> {
        self.failure_code.as_ref()
    }
    /// <p>Returned if there is a failure on the change set, but that failure is not related to any of the changes in the request.</p>
    pub fn failure_description(&self) -> ::std::option::Option<&str> {
        self.failure_description.as_deref()
    }
    /// <p>An array of <code>ChangeSummary</code> objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.change_set.is_none()`.
    pub fn change_set(&self) -> &[crate::types::ChangeSummary] {
        self.change_set.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeChangeSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeChangeSetOutput {
    /// Creates a new builder-style object to manufacture [`DescribeChangeSetOutput`](crate::operation::describe_change_set::DescribeChangeSetOutput).
    pub fn builder() -> crate::operation::describe_change_set::builders::DescribeChangeSetOutputBuilder {
        crate::operation::describe_change_set::builders::DescribeChangeSetOutputBuilder::default()
    }
}

/// A builder for [`DescribeChangeSetOutput`](crate::operation::describe_change_set::DescribeChangeSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeChangeSetOutputBuilder {
    pub(crate) change_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) change_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) intent: ::std::option::Option<crate::types::Intent>,
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
    pub(crate) end_time: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ChangeStatus>,
    pub(crate) failure_code: ::std::option::Option<crate::types::FailureCode>,
    pub(crate) failure_description: ::std::option::Option<::std::string::String>,
    pub(crate) change_set: ::std::option::Option<::std::vec::Vec<crate::types::ChangeSummary>>,
    _request_id: Option<String>,
}
impl DescribeChangeSetOutputBuilder {
    /// <p>Required. The unique identifier for the change set referenced in this request.</p>
    pub fn change_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required. The unique identifier for the change set referenced in this request.</p>
    pub fn set_change_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_set_id = input;
        self
    }
    /// <p>Required. The unique identifier for the change set referenced in this request.</p>
    pub fn get_change_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_set_id
    }
    /// <p>The ARN associated with the unique identifier for the change set referenced in this request.</p>
    pub fn change_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN associated with the unique identifier for the change set referenced in this request.</p>
    pub fn set_change_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_set_arn = input;
        self
    }
    /// <p>The ARN associated with the unique identifier for the change set referenced in this request.</p>
    pub fn get_change_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_set_arn
    }
    /// <p>The optional name provided in the <code>StartChangeSet</code> request. If you do not provide a name, one is set by default.</p>
    pub fn change_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The optional name provided in the <code>StartChangeSet</code> request. If you do not provide a name, one is set by default.</p>
    pub fn set_change_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_set_name = input;
        self
    }
    /// <p>The optional name provided in the <code>StartChangeSet</code> request. If you do not provide a name, one is set by default.</p>
    pub fn get_change_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_set_name
    }
    /// <p>The optional intent provided in the <code>StartChangeSet</code> request. If you do not provide an intent, <code>APPLY</code> is set by default.</p>
    pub fn intent(mut self, input: crate::types::Intent) -> Self {
        self.intent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The optional intent provided in the <code>StartChangeSet</code> request. If you do not provide an intent, <code>APPLY</code> is set by default.</p>
    pub fn set_intent(mut self, input: ::std::option::Option<crate::types::Intent>) -> Self {
        self.intent = input;
        self
    }
    /// <p>The optional intent provided in the <code>StartChangeSet</code> request. If you do not provide an intent, <code>APPLY</code> is set by default.</p>
    pub fn get_intent(&self) -> &::std::option::Option<crate::types::Intent> {
        &self.intent
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request started.</p>
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request transitioned to a terminal state. The change cannot transition to a different state. Null if the request is not in a terminal state.</p>
    pub fn end_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request transitioned to a terminal state. The change cannot transition to a different state. Null if the request is not in a terminal state.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The date and time, in ISO 8601 format (2018-02-27T13:45:22Z), the request transitioned to a terminal state. The change cannot transition to a different state. Null if the request is not in a terminal state.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_time
    }
    /// <p>The status of the change request.</p>
    pub fn status(mut self, input: crate::types::ChangeStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the change request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ChangeStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the change request.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ChangeStatus> {
        &self.status
    }
    /// <p>Returned if the change set is in <code>FAILED</code> status. Can be either <code>CLIENT_ERROR</code>, which means that there are issues with the request (see the <code>ErrorDetailList</code>), or <code>SERVER_FAULT</code>, which means that there is a problem in the system, and you should retry your request.</p>
    pub fn failure_code(mut self, input: crate::types::FailureCode) -> Self {
        self.failure_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returned if the change set is in <code>FAILED</code> status. Can be either <code>CLIENT_ERROR</code>, which means that there are issues with the request (see the <code>ErrorDetailList</code>), or <code>SERVER_FAULT</code>, which means that there is a problem in the system, and you should retry your request.</p>
    pub fn set_failure_code(mut self, input: ::std::option::Option<crate::types::FailureCode>) -> Self {
        self.failure_code = input;
        self
    }
    /// <p>Returned if the change set is in <code>FAILED</code> status. Can be either <code>CLIENT_ERROR</code>, which means that there are issues with the request (see the <code>ErrorDetailList</code>), or <code>SERVER_FAULT</code>, which means that there is a problem in the system, and you should retry your request.</p>
    pub fn get_failure_code(&self) -> &::std::option::Option<crate::types::FailureCode> {
        &self.failure_code
    }
    /// <p>Returned if there is a failure on the change set, but that failure is not related to any of the changes in the request.</p>
    pub fn failure_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returned if there is a failure on the change set, but that failure is not related to any of the changes in the request.</p>
    pub fn set_failure_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_description = input;
        self
    }
    /// <p>Returned if there is a failure on the change set, but that failure is not related to any of the changes in the request.</p>
    pub fn get_failure_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_description
    }
    /// Appends an item to `change_set`.
    ///
    /// To override the contents of this collection use [`set_change_set`](Self::set_change_set).
    ///
    /// <p>An array of <code>ChangeSummary</code> objects.</p>
    pub fn change_set(mut self, input: crate::types::ChangeSummary) -> Self {
        let mut v = self.change_set.unwrap_or_default();
        v.push(input);
        self.change_set = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>ChangeSummary</code> objects.</p>
    pub fn set_change_set(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ChangeSummary>>) -> Self {
        self.change_set = input;
        self
    }
    /// <p>An array of <code>ChangeSummary</code> objects.</p>
    pub fn get_change_set(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChangeSummary>> {
        &self.change_set
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeChangeSetOutput`](crate::operation::describe_change_set::DescribeChangeSetOutput).
    pub fn build(self) -> crate::operation::describe_change_set::DescribeChangeSetOutput {
        crate::operation::describe_change_set::DescribeChangeSetOutput {
            change_set_id: self.change_set_id,
            change_set_arn: self.change_set_arn,
            change_set_name: self.change_set_name,
            intent: self.intent,
            start_time: self.start_time,
            end_time: self.end_time,
            status: self.status,
            failure_code: self.failure_code,
            failure_description: self.failure_description,
            change_set: self.change_set,
            _request_id: self._request_id,
        }
    }
}
