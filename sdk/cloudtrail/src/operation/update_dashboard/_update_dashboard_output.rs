// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDashboardOutput {
    /// <p>The ARN for the dashboard.</p>
    pub dashboard_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name for the dashboard.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of dashboard.</p>
    pub r#type: ::std::option::Option<crate::types::DashboardType>,
    /// <p>An array of widgets for the dashboard.</p>
    pub widgets: ::std::option::Option<::std::vec::Vec<crate::types::Widget>>,
    /// <p>The refresh schedule for the dashboard, if configured.</p>
    pub refresh_schedule: ::std::option::Option<crate::types::RefreshSchedule>,
    /// <p>Indicates whether termination protection is enabled for the dashboard.</p>
    pub termination_protection_enabled: ::std::option::Option<bool>,
    /// <p>The timestamp that shows when the dashboard was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp that shows when the dashboard was updated.</p>
    pub updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl UpdateDashboardOutput {
    /// <p>The ARN for the dashboard.</p>
    pub fn dashboard_arn(&self) -> ::std::option::Option<&str> {
        self.dashboard_arn.as_deref()
    }
    /// <p>The name for the dashboard.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of dashboard.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::DashboardType> {
        self.r#type.as_ref()
    }
    /// <p>An array of widgets for the dashboard.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.widgets.is_none()`.
    pub fn widgets(&self) -> &[crate::types::Widget] {
        self.widgets.as_deref().unwrap_or_default()
    }
    /// <p>The refresh schedule for the dashboard, if configured.</p>
    pub fn refresh_schedule(&self) -> ::std::option::Option<&crate::types::RefreshSchedule> {
        self.refresh_schedule.as_ref()
    }
    /// <p>Indicates whether termination protection is enabled for the dashboard.</p>
    pub fn termination_protection_enabled(&self) -> ::std::option::Option<bool> {
        self.termination_protection_enabled
    }
    /// <p>The timestamp that shows when the dashboard was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The timestamp that shows when the dashboard was updated.</p>
    pub fn updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_timestamp.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDashboardOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDashboardOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDashboardOutput`](crate::operation::update_dashboard::UpdateDashboardOutput).
    pub fn builder() -> crate::operation::update_dashboard::builders::UpdateDashboardOutputBuilder {
        crate::operation::update_dashboard::builders::UpdateDashboardOutputBuilder::default()
    }
}

/// A builder for [`UpdateDashboardOutput`](crate::operation::update_dashboard::UpdateDashboardOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDashboardOutputBuilder {
    pub(crate) dashboard_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::DashboardType>,
    pub(crate) widgets: ::std::option::Option<::std::vec::Vec<crate::types::Widget>>,
    pub(crate) refresh_schedule: ::std::option::Option<crate::types::RefreshSchedule>,
    pub(crate) termination_protection_enabled: ::std::option::Option<bool>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl UpdateDashboardOutputBuilder {
    /// <p>The ARN for the dashboard.</p>
    pub fn dashboard_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the dashboard.</p>
    pub fn set_dashboard_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_arn = input;
        self
    }
    /// <p>The ARN for the dashboard.</p>
    pub fn get_dashboard_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_arn
    }
    /// <p>The name for the dashboard.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the dashboard.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the dashboard.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of dashboard.</p>
    pub fn r#type(mut self, input: crate::types::DashboardType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of dashboard.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DashboardType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of dashboard.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DashboardType> {
        &self.r#type
    }
    /// Appends an item to `widgets`.
    ///
    /// To override the contents of this collection use [`set_widgets`](Self::set_widgets).
    ///
    /// <p>An array of widgets for the dashboard.</p>
    pub fn widgets(mut self, input: crate::types::Widget) -> Self {
        let mut v = self.widgets.unwrap_or_default();
        v.push(input);
        self.widgets = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of widgets for the dashboard.</p>
    pub fn set_widgets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Widget>>) -> Self {
        self.widgets = input;
        self
    }
    /// <p>An array of widgets for the dashboard.</p>
    pub fn get_widgets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Widget>> {
        &self.widgets
    }
    /// <p>The refresh schedule for the dashboard, if configured.</p>
    pub fn refresh_schedule(mut self, input: crate::types::RefreshSchedule) -> Self {
        self.refresh_schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The refresh schedule for the dashboard, if configured.</p>
    pub fn set_refresh_schedule(mut self, input: ::std::option::Option<crate::types::RefreshSchedule>) -> Self {
        self.refresh_schedule = input;
        self
    }
    /// <p>The refresh schedule for the dashboard, if configured.</p>
    pub fn get_refresh_schedule(&self) -> &::std::option::Option<crate::types::RefreshSchedule> {
        &self.refresh_schedule
    }
    /// <p>Indicates whether termination protection is enabled for the dashboard.</p>
    pub fn termination_protection_enabled(mut self, input: bool) -> Self {
        self.termination_protection_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether termination protection is enabled for the dashboard.</p>
    pub fn set_termination_protection_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.termination_protection_enabled = input;
        self
    }
    /// <p>Indicates whether termination protection is enabled for the dashboard.</p>
    pub fn get_termination_protection_enabled(&self) -> &::std::option::Option<bool> {
        &self.termination_protection_enabled
    }
    /// <p>The timestamp that shows when the dashboard was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that shows when the dashboard was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The timestamp that shows when the dashboard was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The timestamp that shows when the dashboard was updated.</p>
    pub fn updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that shows when the dashboard was updated.</p>
    pub fn set_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_timestamp = input;
        self
    }
    /// <p>The timestamp that shows when the dashboard was updated.</p>
    pub fn get_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_timestamp
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDashboardOutput`](crate::operation::update_dashboard::UpdateDashboardOutput).
    pub fn build(self) -> crate::operation::update_dashboard::UpdateDashboardOutput {
        crate::operation::update_dashboard::UpdateDashboardOutput {
            dashboard_arn: self.dashboard_arn,
            name: self.name,
            r#type: self.r#type,
            widgets: self.widgets,
            refresh_schedule: self.refresh_schedule,
            termination_protection_enabled: self.termination_protection_enabled,
            created_timestamp: self.created_timestamp,
            updated_timestamp: self.updated_timestamp,
            _request_id: self._request_id,
        }
    }
}
