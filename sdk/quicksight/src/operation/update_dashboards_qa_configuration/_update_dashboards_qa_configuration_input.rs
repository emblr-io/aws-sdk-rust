// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDashboardsQaConfigurationInput {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard QA configuration that you want to update.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of dashboards QA configuration that you want to update.</p>
    pub dashboards_qa_status: ::std::option::Option<crate::types::DashboardsQaStatus>,
}
impl UpdateDashboardsQaConfigurationInput {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard QA configuration that you want to update.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The status of dashboards QA configuration that you want to update.</p>
    pub fn dashboards_qa_status(&self) -> ::std::option::Option<&crate::types::DashboardsQaStatus> {
        self.dashboards_qa_status.as_ref()
    }
}
impl UpdateDashboardsQaConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateDashboardsQaConfigurationInput`](crate::operation::update_dashboards_qa_configuration::UpdateDashboardsQaConfigurationInput).
    pub fn builder() -> crate::operation::update_dashboards_qa_configuration::builders::UpdateDashboardsQaConfigurationInputBuilder {
        crate::operation::update_dashboards_qa_configuration::builders::UpdateDashboardsQaConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateDashboardsQaConfigurationInput`](crate::operation::update_dashboards_qa_configuration::UpdateDashboardsQaConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDashboardsQaConfigurationInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) dashboards_qa_status: ::std::option::Option<crate::types::DashboardsQaStatus>,
}
impl UpdateDashboardsQaConfigurationInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the dashboard QA configuration that you want to update.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the dashboard QA configuration that you want to update.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the dashboard QA configuration that you want to update.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The status of dashboards QA configuration that you want to update.</p>
    /// This field is required.
    pub fn dashboards_qa_status(mut self, input: crate::types::DashboardsQaStatus) -> Self {
        self.dashboards_qa_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of dashboards QA configuration that you want to update.</p>
    pub fn set_dashboards_qa_status(mut self, input: ::std::option::Option<crate::types::DashboardsQaStatus>) -> Self {
        self.dashboards_qa_status = input;
        self
    }
    /// <p>The status of dashboards QA configuration that you want to update.</p>
    pub fn get_dashboards_qa_status(&self) -> &::std::option::Option<crate::types::DashboardsQaStatus> {
        &self.dashboards_qa_status
    }
    /// Consumes the builder and constructs a [`UpdateDashboardsQaConfigurationInput`](crate::operation::update_dashboards_qa_configuration::UpdateDashboardsQaConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_dashboards_qa_configuration::UpdateDashboardsQaConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_dashboards_qa_configuration::UpdateDashboardsQaConfigurationInput {
                aws_account_id: self.aws_account_id,
                dashboards_qa_status: self.dashboards_qa_status,
            },
        )
    }
}
