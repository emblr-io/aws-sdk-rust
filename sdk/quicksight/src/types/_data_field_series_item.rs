// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The data field series item configuration of a line chart.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DataFieldSeriesItem {
    /// <p>The field ID of the field that you are setting the axis binding to.</p>
    pub field_id: ::std::string::String,
    /// <p>The field value of the field that you are setting the axis binding to.</p>
    pub field_value: ::std::option::Option<::std::string::String>,
    /// <p>The axis that you are binding the field to.</p>
    pub axis_binding: crate::types::AxisBinding,
    /// <p>The options that determine the presentation of line series associated to the field.</p>
    pub settings: ::std::option::Option<crate::types::LineChartSeriesSettings>,
}
impl DataFieldSeriesItem {
    /// <p>The field ID of the field that you are setting the axis binding to.</p>
    pub fn field_id(&self) -> &str {
        use std::ops::Deref;
        self.field_id.deref()
    }
    /// <p>The field value of the field that you are setting the axis binding to.</p>
    pub fn field_value(&self) -> ::std::option::Option<&str> {
        self.field_value.as_deref()
    }
    /// <p>The axis that you are binding the field to.</p>
    pub fn axis_binding(&self) -> &crate::types::AxisBinding {
        &self.axis_binding
    }
    /// <p>The options that determine the presentation of line series associated to the field.</p>
    pub fn settings(&self) -> ::std::option::Option<&crate::types::LineChartSeriesSettings> {
        self.settings.as_ref()
    }
}
impl ::std::fmt::Debug for DataFieldSeriesItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DataFieldSeriesItem");
        formatter.field("field_id", &self.field_id);
        formatter.field("field_value", &"*** Sensitive Data Redacted ***");
        formatter.field("axis_binding", &self.axis_binding);
        formatter.field("settings", &self.settings);
        formatter.finish()
    }
}
impl DataFieldSeriesItem {
    /// Creates a new builder-style object to manufacture [`DataFieldSeriesItem`](crate::types::DataFieldSeriesItem).
    pub fn builder() -> crate::types::builders::DataFieldSeriesItemBuilder {
        crate::types::builders::DataFieldSeriesItemBuilder::default()
    }
}

/// A builder for [`DataFieldSeriesItem`](crate::types::DataFieldSeriesItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DataFieldSeriesItemBuilder {
    pub(crate) field_id: ::std::option::Option<::std::string::String>,
    pub(crate) field_value: ::std::option::Option<::std::string::String>,
    pub(crate) axis_binding: ::std::option::Option<crate::types::AxisBinding>,
    pub(crate) settings: ::std::option::Option<crate::types::LineChartSeriesSettings>,
}
impl DataFieldSeriesItemBuilder {
    /// <p>The field ID of the field that you are setting the axis binding to.</p>
    /// This field is required.
    pub fn field_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The field ID of the field that you are setting the axis binding to.</p>
    pub fn set_field_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field_id = input;
        self
    }
    /// <p>The field ID of the field that you are setting the axis binding to.</p>
    pub fn get_field_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.field_id
    }
    /// <p>The field value of the field that you are setting the axis binding to.</p>
    pub fn field_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The field value of the field that you are setting the axis binding to.</p>
    pub fn set_field_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field_value = input;
        self
    }
    /// <p>The field value of the field that you are setting the axis binding to.</p>
    pub fn get_field_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.field_value
    }
    /// <p>The axis that you are binding the field to.</p>
    /// This field is required.
    pub fn axis_binding(mut self, input: crate::types::AxisBinding) -> Self {
        self.axis_binding = ::std::option::Option::Some(input);
        self
    }
    /// <p>The axis that you are binding the field to.</p>
    pub fn set_axis_binding(mut self, input: ::std::option::Option<crate::types::AxisBinding>) -> Self {
        self.axis_binding = input;
        self
    }
    /// <p>The axis that you are binding the field to.</p>
    pub fn get_axis_binding(&self) -> &::std::option::Option<crate::types::AxisBinding> {
        &self.axis_binding
    }
    /// <p>The options that determine the presentation of line series associated to the field.</p>
    pub fn settings(mut self, input: crate::types::LineChartSeriesSettings) -> Self {
        self.settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the presentation of line series associated to the field.</p>
    pub fn set_settings(mut self, input: ::std::option::Option<crate::types::LineChartSeriesSettings>) -> Self {
        self.settings = input;
        self
    }
    /// <p>The options that determine the presentation of line series associated to the field.</p>
    pub fn get_settings(&self) -> &::std::option::Option<crate::types::LineChartSeriesSettings> {
        &self.settings
    }
    /// Consumes the builder and constructs a [`DataFieldSeriesItem`](crate::types::DataFieldSeriesItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`field_id`](crate::types::builders::DataFieldSeriesItemBuilder::field_id)
    /// - [`axis_binding`](crate::types::builders::DataFieldSeriesItemBuilder::axis_binding)
    pub fn build(self) -> ::std::result::Result<crate::types::DataFieldSeriesItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataFieldSeriesItem {
            field_id: self.field_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "field_id",
                    "field_id was not specified but it is required when building DataFieldSeriesItem",
                )
            })?,
            field_value: self.field_value,
            axis_binding: self.axis_binding.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "axis_binding",
                    "axis_binding was not specified but it is required when building DataFieldSeriesItem",
                )
            })?,
            settings: self.settings,
        })
    }
}
impl ::std::fmt::Debug for DataFieldSeriesItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DataFieldSeriesItemBuilder");
        formatter.field("field_id", &self.field_id);
        formatter.field("field_value", &"*** Sensitive Data Redacted ***");
        formatter.field("axis_binding", &self.axis_binding);
        formatter.field("settings", &self.settings);
        formatter.finish()
    }
}
