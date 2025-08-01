// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateApprovalRuleTemplateDescriptionOutput {
    /// <p>The structure and content of the updated approval rule template.</p>
    pub approval_rule_template: ::std::option::Option<crate::types::ApprovalRuleTemplate>,
    _request_id: Option<String>,
}
impl UpdateApprovalRuleTemplateDescriptionOutput {
    /// <p>The structure and content of the updated approval rule template.</p>
    pub fn approval_rule_template(&self) -> ::std::option::Option<&crate::types::ApprovalRuleTemplate> {
        self.approval_rule_template.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateApprovalRuleTemplateDescriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateApprovalRuleTemplateDescriptionOutput {
    /// Creates a new builder-style object to manufacture [`UpdateApprovalRuleTemplateDescriptionOutput`](crate::operation::update_approval_rule_template_description::UpdateApprovalRuleTemplateDescriptionOutput).
    pub fn builder() -> crate::operation::update_approval_rule_template_description::builders::UpdateApprovalRuleTemplateDescriptionOutputBuilder {
        crate::operation::update_approval_rule_template_description::builders::UpdateApprovalRuleTemplateDescriptionOutputBuilder::default()
    }
}

/// A builder for [`UpdateApprovalRuleTemplateDescriptionOutput`](crate::operation::update_approval_rule_template_description::UpdateApprovalRuleTemplateDescriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateApprovalRuleTemplateDescriptionOutputBuilder {
    pub(crate) approval_rule_template: ::std::option::Option<crate::types::ApprovalRuleTemplate>,
    _request_id: Option<String>,
}
impl UpdateApprovalRuleTemplateDescriptionOutputBuilder {
    /// <p>The structure and content of the updated approval rule template.</p>
    /// This field is required.
    pub fn approval_rule_template(mut self, input: crate::types::ApprovalRuleTemplate) -> Self {
        self.approval_rule_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>The structure and content of the updated approval rule template.</p>
    pub fn set_approval_rule_template(mut self, input: ::std::option::Option<crate::types::ApprovalRuleTemplate>) -> Self {
        self.approval_rule_template = input;
        self
    }
    /// <p>The structure and content of the updated approval rule template.</p>
    pub fn get_approval_rule_template(&self) -> &::std::option::Option<crate::types::ApprovalRuleTemplate> {
        &self.approval_rule_template
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateApprovalRuleTemplateDescriptionOutput`](crate::operation::update_approval_rule_template_description::UpdateApprovalRuleTemplateDescriptionOutput).
    pub fn build(self) -> crate::operation::update_approval_rule_template_description::UpdateApprovalRuleTemplateDescriptionOutput {
        crate::operation::update_approval_rule_template_description::UpdateApprovalRuleTemplateDescriptionOutput {
            approval_rule_template: self.approval_rule_template,
            _request_id: self._request_id,
        }
    }
}
