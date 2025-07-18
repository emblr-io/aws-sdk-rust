// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateReportGroupOutput {
    /// <p>Information about the updated report group.</p>
    pub report_group: ::std::option::Option<crate::types::ReportGroup>,
    _request_id: Option<String>,
}
impl UpdateReportGroupOutput {
    /// <p>Information about the updated report group.</p>
    pub fn report_group(&self) -> ::std::option::Option<&crate::types::ReportGroup> {
        self.report_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateReportGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateReportGroupOutput {
    /// Creates a new builder-style object to manufacture [`UpdateReportGroupOutput`](crate::operation::update_report_group::UpdateReportGroupOutput).
    pub fn builder() -> crate::operation::update_report_group::builders::UpdateReportGroupOutputBuilder {
        crate::operation::update_report_group::builders::UpdateReportGroupOutputBuilder::default()
    }
}

/// A builder for [`UpdateReportGroupOutput`](crate::operation::update_report_group::UpdateReportGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateReportGroupOutputBuilder {
    pub(crate) report_group: ::std::option::Option<crate::types::ReportGroup>,
    _request_id: Option<String>,
}
impl UpdateReportGroupOutputBuilder {
    /// <p>Information about the updated report group.</p>
    pub fn report_group(mut self, input: crate::types::ReportGroup) -> Self {
        self.report_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the updated report group.</p>
    pub fn set_report_group(mut self, input: ::std::option::Option<crate::types::ReportGroup>) -> Self {
        self.report_group = input;
        self
    }
    /// <p>Information about the updated report group.</p>
    pub fn get_report_group(&self) -> &::std::option::Option<crate::types::ReportGroup> {
        &self.report_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateReportGroupOutput`](crate::operation::update_report_group::UpdateReportGroupOutput).
    pub fn build(self) -> crate::operation::update_report_group::UpdateReportGroupOutput {
        crate::operation::update_report_group::UpdateReportGroupOutput {
            report_group: self.report_group,
            _request_id: self._request_id,
        }
    }
}
