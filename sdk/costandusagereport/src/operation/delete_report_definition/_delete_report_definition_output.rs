// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>If the action is successful, the service sends back an HTTP 200 response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReportDefinitionOutput {
    /// <p>Whether the deletion was successful or not.</p>
    pub response_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteReportDefinitionOutput {
    /// <p>Whether the deletion was successful or not.</p>
    pub fn response_message(&self) -> ::std::option::Option<&str> {
        self.response_message.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteReportDefinitionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteReportDefinitionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteReportDefinitionOutput`](crate::operation::delete_report_definition::DeleteReportDefinitionOutput).
    pub fn builder() -> crate::operation::delete_report_definition::builders::DeleteReportDefinitionOutputBuilder {
        crate::operation::delete_report_definition::builders::DeleteReportDefinitionOutputBuilder::default()
    }
}

/// A builder for [`DeleteReportDefinitionOutput`](crate::operation::delete_report_definition::DeleteReportDefinitionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReportDefinitionOutputBuilder {
    pub(crate) response_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteReportDefinitionOutputBuilder {
    /// <p>Whether the deletion was successful or not.</p>
    pub fn response_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.response_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Whether the deletion was successful or not.</p>
    pub fn set_response_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.response_message = input;
        self
    }
    /// <p>Whether the deletion was successful or not.</p>
    pub fn get_response_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.response_message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteReportDefinitionOutput`](crate::operation::delete_report_definition::DeleteReportDefinitionOutput).
    pub fn build(self) -> crate::operation::delete_report_definition::DeleteReportDefinitionOutput {
        crate::operation::delete_report_definition::DeleteReportDefinitionOutput {
            response_message: self.response_message,
            _request_id: self._request_id,
        }
    }
}
