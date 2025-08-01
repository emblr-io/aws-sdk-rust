// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReportCreationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StartReportCreationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartReportCreationOutput {
    /// Creates a new builder-style object to manufacture [`StartReportCreationOutput`](crate::operation::start_report_creation::StartReportCreationOutput).
    pub fn builder() -> crate::operation::start_report_creation::builders::StartReportCreationOutputBuilder {
        crate::operation::start_report_creation::builders::StartReportCreationOutputBuilder::default()
    }
}

/// A builder for [`StartReportCreationOutput`](crate::operation::start_report_creation::StartReportCreationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReportCreationOutputBuilder {
    _request_id: Option<String>,
}
impl StartReportCreationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartReportCreationOutput`](crate::operation::start_report_creation::StartReportCreationOutput).
    pub fn build(self) -> crate::operation::start_report_creation::StartReportCreationOutput {
        crate::operation::start_report_creation::StartReportCreationOutput {
            _request_id: self._request_id,
        }
    }
}
