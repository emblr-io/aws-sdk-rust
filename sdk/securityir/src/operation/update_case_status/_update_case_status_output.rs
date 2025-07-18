// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateCaseStatusOutput {
    /// <p>Response element for UpdateCaseStatus showing the newly configured status.</p>
    pub case_status: ::std::option::Option<crate::types::SelfManagedCaseStatus>,
    _request_id: Option<String>,
}
impl UpdateCaseStatusOutput {
    /// <p>Response element for UpdateCaseStatus showing the newly configured status.</p>
    pub fn case_status(&self) -> ::std::option::Option<&crate::types::SelfManagedCaseStatus> {
        self.case_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateCaseStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateCaseStatusOutput {
    /// Creates a new builder-style object to manufacture [`UpdateCaseStatusOutput`](crate::operation::update_case_status::UpdateCaseStatusOutput).
    pub fn builder() -> crate::operation::update_case_status::builders::UpdateCaseStatusOutputBuilder {
        crate::operation::update_case_status::builders::UpdateCaseStatusOutputBuilder::default()
    }
}

/// A builder for [`UpdateCaseStatusOutput`](crate::operation::update_case_status::UpdateCaseStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateCaseStatusOutputBuilder {
    pub(crate) case_status: ::std::option::Option<crate::types::SelfManagedCaseStatus>,
    _request_id: Option<String>,
}
impl UpdateCaseStatusOutputBuilder {
    /// <p>Response element for UpdateCaseStatus showing the newly configured status.</p>
    pub fn case_status(mut self, input: crate::types::SelfManagedCaseStatus) -> Self {
        self.case_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Response element for UpdateCaseStatus showing the newly configured status.</p>
    pub fn set_case_status(mut self, input: ::std::option::Option<crate::types::SelfManagedCaseStatus>) -> Self {
        self.case_status = input;
        self
    }
    /// <p>Response element for UpdateCaseStatus showing the newly configured status.</p>
    pub fn get_case_status(&self) -> &::std::option::Option<crate::types::SelfManagedCaseStatus> {
        &self.case_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateCaseStatusOutput`](crate::operation::update_case_status::UpdateCaseStatusOutput).
    pub fn build(self) -> crate::operation::update_case_status::UpdateCaseStatusOutput {
        crate::operation::update_case_status::UpdateCaseStatusOutput {
            case_status: self.case_status,
            _request_id: self._request_id,
        }
    }
}
