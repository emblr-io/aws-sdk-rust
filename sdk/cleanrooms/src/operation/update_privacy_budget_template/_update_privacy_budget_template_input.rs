// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdatePrivacyBudgetTemplateInput {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget template is updated in the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for your privacy budget template that you want to update.</p>
    pub privacy_budget_template_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the type of the privacy budget template.</p>
    pub privacy_budget_type: ::std::option::Option<crate::types::PrivacyBudgetType>,
    /// <p>Specifies the epsilon and noise parameters for the privacy budget template.</p>
    pub parameters: ::std::option::Option<crate::types::PrivacyBudgetTemplateUpdateParameters>,
}
impl UpdatePrivacyBudgetTemplateInput {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget template is updated in the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>A unique identifier for your privacy budget template that you want to update.</p>
    pub fn privacy_budget_template_identifier(&self) -> ::std::option::Option<&str> {
        self.privacy_budget_template_identifier.as_deref()
    }
    /// <p>Specifies the type of the privacy budget template.</p>
    pub fn privacy_budget_type(&self) -> ::std::option::Option<&crate::types::PrivacyBudgetType> {
        self.privacy_budget_type.as_ref()
    }
    /// <p>Specifies the epsilon and noise parameters for the privacy budget template.</p>
    pub fn parameters(&self) -> ::std::option::Option<&crate::types::PrivacyBudgetTemplateUpdateParameters> {
        self.parameters.as_ref()
    }
}
impl UpdatePrivacyBudgetTemplateInput {
    /// Creates a new builder-style object to manufacture [`UpdatePrivacyBudgetTemplateInput`](crate::operation::update_privacy_budget_template::UpdatePrivacyBudgetTemplateInput).
    pub fn builder() -> crate::operation::update_privacy_budget_template::builders::UpdatePrivacyBudgetTemplateInputBuilder {
        crate::operation::update_privacy_budget_template::builders::UpdatePrivacyBudgetTemplateInputBuilder::default()
    }
}

/// A builder for [`UpdatePrivacyBudgetTemplateInput`](crate::operation::update_privacy_budget_template::UpdatePrivacyBudgetTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdatePrivacyBudgetTemplateInputBuilder {
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) privacy_budget_template_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) privacy_budget_type: ::std::option::Option<crate::types::PrivacyBudgetType>,
    pub(crate) parameters: ::std::option::Option<crate::types::PrivacyBudgetTemplateUpdateParameters>,
}
impl UpdatePrivacyBudgetTemplateInputBuilder {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget template is updated in the collaboration that this membership belongs to. Accepts a membership ID.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget template is updated in the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget template is updated in the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// <p>A unique identifier for your privacy budget template that you want to update.</p>
    /// This field is required.
    pub fn privacy_budget_template_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.privacy_budget_template_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for your privacy budget template that you want to update.</p>
    pub fn set_privacy_budget_template_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.privacy_budget_template_identifier = input;
        self
    }
    /// <p>A unique identifier for your privacy budget template that you want to update.</p>
    pub fn get_privacy_budget_template_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.privacy_budget_template_identifier
    }
    /// <p>Specifies the type of the privacy budget template.</p>
    /// This field is required.
    pub fn privacy_budget_type(mut self, input: crate::types::PrivacyBudgetType) -> Self {
        self.privacy_budget_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of the privacy budget template.</p>
    pub fn set_privacy_budget_type(mut self, input: ::std::option::Option<crate::types::PrivacyBudgetType>) -> Self {
        self.privacy_budget_type = input;
        self
    }
    /// <p>Specifies the type of the privacy budget template.</p>
    pub fn get_privacy_budget_type(&self) -> &::std::option::Option<crate::types::PrivacyBudgetType> {
        &self.privacy_budget_type
    }
    /// <p>Specifies the epsilon and noise parameters for the privacy budget template.</p>
    pub fn parameters(mut self, input: crate::types::PrivacyBudgetTemplateUpdateParameters) -> Self {
        self.parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the epsilon and noise parameters for the privacy budget template.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<crate::types::PrivacyBudgetTemplateUpdateParameters>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>Specifies the epsilon and noise parameters for the privacy budget template.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<crate::types::PrivacyBudgetTemplateUpdateParameters> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`UpdatePrivacyBudgetTemplateInput`](crate::operation::update_privacy_budget_template::UpdatePrivacyBudgetTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_privacy_budget_template::UpdatePrivacyBudgetTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_privacy_budget_template::UpdatePrivacyBudgetTemplateInput {
            membership_identifier: self.membership_identifier,
            privacy_budget_template_identifier: self.privacy_budget_template_identifier,
            privacy_budget_type: self.privacy_budget_type,
            parameters: self.parameters,
        })
    }
}
