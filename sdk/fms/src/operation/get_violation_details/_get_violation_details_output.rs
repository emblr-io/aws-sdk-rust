// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetViolationDetailsOutput {
    /// <p>Violation detail for a resource.</p>
    pub violation_detail: ::std::option::Option<crate::types::ViolationDetail>,
    _request_id: Option<String>,
}
impl GetViolationDetailsOutput {
    /// <p>Violation detail for a resource.</p>
    pub fn violation_detail(&self) -> ::std::option::Option<&crate::types::ViolationDetail> {
        self.violation_detail.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetViolationDetailsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetViolationDetailsOutput {
    /// Creates a new builder-style object to manufacture [`GetViolationDetailsOutput`](crate::operation::get_violation_details::GetViolationDetailsOutput).
    pub fn builder() -> crate::operation::get_violation_details::builders::GetViolationDetailsOutputBuilder {
        crate::operation::get_violation_details::builders::GetViolationDetailsOutputBuilder::default()
    }
}

/// A builder for [`GetViolationDetailsOutput`](crate::operation::get_violation_details::GetViolationDetailsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetViolationDetailsOutputBuilder {
    pub(crate) violation_detail: ::std::option::Option<crate::types::ViolationDetail>,
    _request_id: Option<String>,
}
impl GetViolationDetailsOutputBuilder {
    /// <p>Violation detail for a resource.</p>
    pub fn violation_detail(mut self, input: crate::types::ViolationDetail) -> Self {
        self.violation_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Violation detail for a resource.</p>
    pub fn set_violation_detail(mut self, input: ::std::option::Option<crate::types::ViolationDetail>) -> Self {
        self.violation_detail = input;
        self
    }
    /// <p>Violation detail for a resource.</p>
    pub fn get_violation_detail(&self) -> &::std::option::Option<crate::types::ViolationDetail> {
        &self.violation_detail
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetViolationDetailsOutput`](crate::operation::get_violation_details::GetViolationDetailsOutput).
    pub fn build(self) -> crate::operation::get_violation_details::GetViolationDetailsOutput {
        crate::operation::get_violation_details::GetViolationDetailsOutput {
            violation_detail: self.violation_detail,
            _request_id: self._request_id,
        }
    }
}
