// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloseCaseOutput {
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case status following the action.</p>
    pub case_status: ::std::option::Option<crate::types::CaseStatus>,
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case closure date following the action.</p>
    pub closed_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CloseCaseOutput {
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case status following the action.</p>
    pub fn case_status(&self) -> ::std::option::Option<&crate::types::CaseStatus> {
        self.case_status.as_ref()
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case closure date following the action.</p>
    pub fn closed_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.closed_date.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CloseCaseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CloseCaseOutput {
    /// Creates a new builder-style object to manufacture [`CloseCaseOutput`](crate::operation::close_case::CloseCaseOutput).
    pub fn builder() -> crate::operation::close_case::builders::CloseCaseOutputBuilder {
        crate::operation::close_case::builders::CloseCaseOutputBuilder::default()
    }
}

/// A builder for [`CloseCaseOutput`](crate::operation::close_case::CloseCaseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloseCaseOutputBuilder {
    pub(crate) case_status: ::std::option::Option<crate::types::CaseStatus>,
    pub(crate) closed_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CloseCaseOutputBuilder {
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case status following the action.</p>
    pub fn case_status(mut self, input: crate::types::CaseStatus) -> Self {
        self.case_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case status following the action.</p>
    pub fn set_case_status(mut self, input: ::std::option::Option<crate::types::CaseStatus>) -> Self {
        self.case_status = input;
        self
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case status following the action.</p>
    pub fn get_case_status(&self) -> &::std::option::Option<crate::types::CaseStatus> {
        &self.case_status
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case closure date following the action.</p>
    pub fn closed_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.closed_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case closure date following the action.</p>
    pub fn set_closed_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.closed_date = input;
        self
    }
    /// <p>A response element providing responses for requests to CloseCase. This element responds with the case closure date following the action.</p>
    pub fn get_closed_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.closed_date
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CloseCaseOutput`](crate::operation::close_case::CloseCaseOutput).
    pub fn build(self) -> crate::operation::close_case::CloseCaseOutput {
        crate::operation::close_case::CloseCaseOutput {
            case_status: self.case_status,
            closed_date: self.closed_date,
            _request_id: self._request_id,
        }
    }
}
