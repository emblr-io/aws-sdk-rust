// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetColumnStatisticsTaskSettingsOutput {
    /// <p>A <code>ColumnStatisticsTaskSettings</code> object representing the settings for the column statistics task.</p>
    pub column_statistics_task_settings: ::std::option::Option<crate::types::ColumnStatisticsTaskSettings>,
    _request_id: Option<String>,
}
impl GetColumnStatisticsTaskSettingsOutput {
    /// <p>A <code>ColumnStatisticsTaskSettings</code> object representing the settings for the column statistics task.</p>
    pub fn column_statistics_task_settings(&self) -> ::std::option::Option<&crate::types::ColumnStatisticsTaskSettings> {
        self.column_statistics_task_settings.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetColumnStatisticsTaskSettingsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetColumnStatisticsTaskSettingsOutput {
    /// Creates a new builder-style object to manufacture [`GetColumnStatisticsTaskSettingsOutput`](crate::operation::get_column_statistics_task_settings::GetColumnStatisticsTaskSettingsOutput).
    pub fn builder() -> crate::operation::get_column_statistics_task_settings::builders::GetColumnStatisticsTaskSettingsOutputBuilder {
        crate::operation::get_column_statistics_task_settings::builders::GetColumnStatisticsTaskSettingsOutputBuilder::default()
    }
}

/// A builder for [`GetColumnStatisticsTaskSettingsOutput`](crate::operation::get_column_statistics_task_settings::GetColumnStatisticsTaskSettingsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetColumnStatisticsTaskSettingsOutputBuilder {
    pub(crate) column_statistics_task_settings: ::std::option::Option<crate::types::ColumnStatisticsTaskSettings>,
    _request_id: Option<String>,
}
impl GetColumnStatisticsTaskSettingsOutputBuilder {
    /// <p>A <code>ColumnStatisticsTaskSettings</code> object representing the settings for the column statistics task.</p>
    pub fn column_statistics_task_settings(mut self, input: crate::types::ColumnStatisticsTaskSettings) -> Self {
        self.column_statistics_task_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>ColumnStatisticsTaskSettings</code> object representing the settings for the column statistics task.</p>
    pub fn set_column_statistics_task_settings(mut self, input: ::std::option::Option<crate::types::ColumnStatisticsTaskSettings>) -> Self {
        self.column_statistics_task_settings = input;
        self
    }
    /// <p>A <code>ColumnStatisticsTaskSettings</code> object representing the settings for the column statistics task.</p>
    pub fn get_column_statistics_task_settings(&self) -> &::std::option::Option<crate::types::ColumnStatisticsTaskSettings> {
        &self.column_statistics_task_settings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetColumnStatisticsTaskSettingsOutput`](crate::operation::get_column_statistics_task_settings::GetColumnStatisticsTaskSettingsOutput).
    pub fn build(self) -> crate::operation::get_column_statistics_task_settings::GetColumnStatisticsTaskSettingsOutput {
        crate::operation::get_column_statistics_task_settings::GetColumnStatisticsTaskSettingsOutput {
            column_statistics_task_settings: self.column_statistics_task_settings,
            _request_id: self._request_id,
        }
    }
}
