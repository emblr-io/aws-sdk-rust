// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPrivacyBudgetTemplateOutput {
    /// <p>Returns the details of the privacy budget template that you requested.</p>
    pub privacy_budget_template: ::std::option::Option<crate::types::PrivacyBudgetTemplate>,
    _request_id: Option<String>,
}
impl GetPrivacyBudgetTemplateOutput {
    /// <p>Returns the details of the privacy budget template that you requested.</p>
    pub fn privacy_budget_template(&self) -> ::std::option::Option<&crate::types::PrivacyBudgetTemplate> {
        self.privacy_budget_template.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPrivacyBudgetTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPrivacyBudgetTemplateOutput {
    /// Creates a new builder-style object to manufacture [`GetPrivacyBudgetTemplateOutput`](crate::operation::get_privacy_budget_template::GetPrivacyBudgetTemplateOutput).
    pub fn builder() -> crate::operation::get_privacy_budget_template::builders::GetPrivacyBudgetTemplateOutputBuilder {
        crate::operation::get_privacy_budget_template::builders::GetPrivacyBudgetTemplateOutputBuilder::default()
    }
}

/// A builder for [`GetPrivacyBudgetTemplateOutput`](crate::operation::get_privacy_budget_template::GetPrivacyBudgetTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPrivacyBudgetTemplateOutputBuilder {
    pub(crate) privacy_budget_template: ::std::option::Option<crate::types::PrivacyBudgetTemplate>,
    _request_id: Option<String>,
}
impl GetPrivacyBudgetTemplateOutputBuilder {
    /// <p>Returns the details of the privacy budget template that you requested.</p>
    /// This field is required.
    pub fn privacy_budget_template(mut self, input: crate::types::PrivacyBudgetTemplate) -> Self {
        self.privacy_budget_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the details of the privacy budget template that you requested.</p>
    pub fn set_privacy_budget_template(mut self, input: ::std::option::Option<crate::types::PrivacyBudgetTemplate>) -> Self {
        self.privacy_budget_template = input;
        self
    }
    /// <p>Returns the details of the privacy budget template that you requested.</p>
    pub fn get_privacy_budget_template(&self) -> &::std::option::Option<crate::types::PrivacyBudgetTemplate> {
        &self.privacy_budget_template
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPrivacyBudgetTemplateOutput`](crate::operation::get_privacy_budget_template::GetPrivacyBudgetTemplateOutput).
    pub fn build(self) -> crate::operation::get_privacy_budget_template::GetPrivacyBudgetTemplateOutput {
        crate::operation::get_privacy_budget_template::GetPrivacyBudgetTemplateOutput {
            privacy_budget_template: self.privacy_budget_template,
            _request_id: self._request_id,
        }
    }
}
