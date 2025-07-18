// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDeclarativePoliciesReportOutput {
    /// <p>The ID of the report.</p>
    pub report_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartDeclarativePoliciesReportOutput {
    /// <p>The ID of the report.</p>
    pub fn report_id(&self) -> ::std::option::Option<&str> {
        self.report_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartDeclarativePoliciesReportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartDeclarativePoliciesReportOutput {
    /// Creates a new builder-style object to manufacture [`StartDeclarativePoliciesReportOutput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportOutput).
    pub fn builder() -> crate::operation::start_declarative_policies_report::builders::StartDeclarativePoliciesReportOutputBuilder {
        crate::operation::start_declarative_policies_report::builders::StartDeclarativePoliciesReportOutputBuilder::default()
    }
}

/// A builder for [`StartDeclarativePoliciesReportOutput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDeclarativePoliciesReportOutputBuilder {
    pub(crate) report_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartDeclarativePoliciesReportOutputBuilder {
    /// <p>The ID of the report.</p>
    pub fn report_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.report_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the report.</p>
    pub fn set_report_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.report_id = input;
        self
    }
    /// <p>The ID of the report.</p>
    pub fn get_report_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.report_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartDeclarativePoliciesReportOutput`](crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportOutput).
    pub fn build(self) -> crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportOutput {
        crate::operation::start_declarative_policies_report::StartDeclarativePoliciesReportOutput {
            report_id: self.report_id,
            _request_id: self._request_id,
        }
    }
}
