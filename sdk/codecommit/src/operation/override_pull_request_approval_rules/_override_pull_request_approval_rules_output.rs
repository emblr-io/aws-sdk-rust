// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OverridePullRequestApprovalRulesOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for OverridePullRequestApprovalRulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl OverridePullRequestApprovalRulesOutput {
    /// Creates a new builder-style object to manufacture [`OverridePullRequestApprovalRulesOutput`](crate::operation::override_pull_request_approval_rules::OverridePullRequestApprovalRulesOutput).
    pub fn builder() -> crate::operation::override_pull_request_approval_rules::builders::OverridePullRequestApprovalRulesOutputBuilder {
        crate::operation::override_pull_request_approval_rules::builders::OverridePullRequestApprovalRulesOutputBuilder::default()
    }
}

/// A builder for [`OverridePullRequestApprovalRulesOutput`](crate::operation::override_pull_request_approval_rules::OverridePullRequestApprovalRulesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OverridePullRequestApprovalRulesOutputBuilder {
    _request_id: Option<String>,
}
impl OverridePullRequestApprovalRulesOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`OverridePullRequestApprovalRulesOutput`](crate::operation::override_pull_request_approval_rules::OverridePullRequestApprovalRulesOutput).
    pub fn build(self) -> crate::operation::override_pull_request_approval_rules::OverridePullRequestApprovalRulesOutput {
        crate::operation::override_pull_request_approval_rules::OverridePullRequestApprovalRulesOutput {
            _request_id: self._request_id,
        }
    }
}
