// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInvestigationGroupPolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteInvestigationGroupPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteInvestigationGroupPolicyOutput {
    /// Creates a new builder-style object to manufacture [`DeleteInvestigationGroupPolicyOutput`](crate::operation::delete_investigation_group_policy::DeleteInvestigationGroupPolicyOutput).
    pub fn builder() -> crate::operation::delete_investigation_group_policy::builders::DeleteInvestigationGroupPolicyOutputBuilder {
        crate::operation::delete_investigation_group_policy::builders::DeleteInvestigationGroupPolicyOutputBuilder::default()
    }
}

/// A builder for [`DeleteInvestigationGroupPolicyOutput`](crate::operation::delete_investigation_group_policy::DeleteInvestigationGroupPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInvestigationGroupPolicyOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteInvestigationGroupPolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteInvestigationGroupPolicyOutput`](crate::operation::delete_investigation_group_policy::DeleteInvestigationGroupPolicyOutput).
    pub fn build(self) -> crate::operation::delete_investigation_group_policy::DeleteInvestigationGroupPolicyOutput {
        crate::operation::delete_investigation_group_policy::DeleteInvestigationGroupPolicyOutput {
            _request_id: self._request_id,
        }
    }
}
