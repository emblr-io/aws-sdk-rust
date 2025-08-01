// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A control to display a list with buttons or boxes that are used to select either a single value or multiple values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParameterListControl {
    /// <p>The ID of the <code>ParameterListControl</code>.</p>
    pub parameter_control_id: ::std::string::String,
    /// <p>The title of the <code>ParameterListControl</code>.</p>
    pub title: ::std::string::String,
    /// <p>The source parameter name of the <code>ParameterListControl</code>.</p>
    pub source_parameter_name: ::std::string::String,
    /// <p>The display options of a control.</p>
    pub display_options: ::std::option::Option<crate::types::ListControlDisplayOptions>,
    /// <p>The type of <code>ParameterListControl</code>.</p>
    pub r#type: ::std::option::Option<crate::types::SheetControlListType>,
    /// <p>A list of selectable values that are used in a control.</p>
    pub selectable_values: ::std::option::Option<crate::types::ParameterSelectableValues>,
    /// <p>The values that are displayed in a control can be configured to only show values that are valid based on what's selected in other controls.</p>
    pub cascading_control_configuration: ::std::option::Option<crate::types::CascadingControlConfiguration>,
}
impl ParameterListControl {
    /// <p>The ID of the <code>ParameterListControl</code>.</p>
    pub fn parameter_control_id(&self) -> &str {
        use std::ops::Deref;
        self.parameter_control_id.deref()
    }
    /// <p>The title of the <code>ParameterListControl</code>.</p>
    pub fn title(&self) -> &str {
        use std::ops::Deref;
        self.title.deref()
    }
    /// <p>The source parameter name of the <code>ParameterListControl</code>.</p>
    pub fn source_parameter_name(&self) -> &str {
        use std::ops::Deref;
        self.source_parameter_name.deref()
    }
    /// <p>The display options of a control.</p>
    pub fn display_options(&self) -> ::std::option::Option<&crate::types::ListControlDisplayOptions> {
        self.display_options.as_ref()
    }
    /// <p>The type of <code>ParameterListControl</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::SheetControlListType> {
        self.r#type.as_ref()
    }
    /// <p>A list of selectable values that are used in a control.</p>
    pub fn selectable_values(&self) -> ::std::option::Option<&crate::types::ParameterSelectableValues> {
        self.selectable_values.as_ref()
    }
    /// <p>The values that are displayed in a control can be configured to only show values that are valid based on what's selected in other controls.</p>
    pub fn cascading_control_configuration(&self) -> ::std::option::Option<&crate::types::CascadingControlConfiguration> {
        self.cascading_control_configuration.as_ref()
    }
}
impl ParameterListControl {
    /// Creates a new builder-style object to manufacture [`ParameterListControl`](crate::types::ParameterListControl).
    pub fn builder() -> crate::types::builders::ParameterListControlBuilder {
        crate::types::builders::ParameterListControlBuilder::default()
    }
}

/// A builder for [`ParameterListControl`](crate::types::ParameterListControl).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterListControlBuilder {
    pub(crate) parameter_control_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) source_parameter_name: ::std::option::Option<::std::string::String>,
    pub(crate) display_options: ::std::option::Option<crate::types::ListControlDisplayOptions>,
    pub(crate) r#type: ::std::option::Option<crate::types::SheetControlListType>,
    pub(crate) selectable_values: ::std::option::Option<crate::types::ParameterSelectableValues>,
    pub(crate) cascading_control_configuration: ::std::option::Option<crate::types::CascadingControlConfiguration>,
}
impl ParameterListControlBuilder {
    /// <p>The ID of the <code>ParameterListControl</code>.</p>
    /// This field is required.
    pub fn parameter_control_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_control_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the <code>ParameterListControl</code>.</p>
    pub fn set_parameter_control_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_control_id = input;
        self
    }
    /// <p>The ID of the <code>ParameterListControl</code>.</p>
    pub fn get_parameter_control_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_control_id
    }
    /// <p>The title of the <code>ParameterListControl</code>.</p>
    /// This field is required.
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the <code>ParameterListControl</code>.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The title of the <code>ParameterListControl</code>.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The source parameter name of the <code>ParameterListControl</code>.</p>
    /// This field is required.
    pub fn source_parameter_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_parameter_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source parameter name of the <code>ParameterListControl</code>.</p>
    pub fn set_source_parameter_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_parameter_name = input;
        self
    }
    /// <p>The source parameter name of the <code>ParameterListControl</code>.</p>
    pub fn get_source_parameter_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_parameter_name
    }
    /// <p>The display options of a control.</p>
    pub fn display_options(mut self, input: crate::types::ListControlDisplayOptions) -> Self {
        self.display_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The display options of a control.</p>
    pub fn set_display_options(mut self, input: ::std::option::Option<crate::types::ListControlDisplayOptions>) -> Self {
        self.display_options = input;
        self
    }
    /// <p>The display options of a control.</p>
    pub fn get_display_options(&self) -> &::std::option::Option<crate::types::ListControlDisplayOptions> {
        &self.display_options
    }
    /// <p>The type of <code>ParameterListControl</code>.</p>
    pub fn r#type(mut self, input: crate::types::SheetControlListType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of <code>ParameterListControl</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::SheetControlListType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of <code>ParameterListControl</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::SheetControlListType> {
        &self.r#type
    }
    /// <p>A list of selectable values that are used in a control.</p>
    pub fn selectable_values(mut self, input: crate::types::ParameterSelectableValues) -> Self {
        self.selectable_values = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of selectable values that are used in a control.</p>
    pub fn set_selectable_values(mut self, input: ::std::option::Option<crate::types::ParameterSelectableValues>) -> Self {
        self.selectable_values = input;
        self
    }
    /// <p>A list of selectable values that are used in a control.</p>
    pub fn get_selectable_values(&self) -> &::std::option::Option<crate::types::ParameterSelectableValues> {
        &self.selectable_values
    }
    /// <p>The values that are displayed in a control can be configured to only show values that are valid based on what's selected in other controls.</p>
    pub fn cascading_control_configuration(mut self, input: crate::types::CascadingControlConfiguration) -> Self {
        self.cascading_control_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The values that are displayed in a control can be configured to only show values that are valid based on what's selected in other controls.</p>
    pub fn set_cascading_control_configuration(mut self, input: ::std::option::Option<crate::types::CascadingControlConfiguration>) -> Self {
        self.cascading_control_configuration = input;
        self
    }
    /// <p>The values that are displayed in a control can be configured to only show values that are valid based on what's selected in other controls.</p>
    pub fn get_cascading_control_configuration(&self) -> &::std::option::Option<crate::types::CascadingControlConfiguration> {
        &self.cascading_control_configuration
    }
    /// Consumes the builder and constructs a [`ParameterListControl`](crate::types::ParameterListControl).
    /// This method will fail if any of the following fields are not set:
    /// - [`parameter_control_id`](crate::types::builders::ParameterListControlBuilder::parameter_control_id)
    /// - [`title`](crate::types::builders::ParameterListControlBuilder::title)
    /// - [`source_parameter_name`](crate::types::builders::ParameterListControlBuilder::source_parameter_name)
    pub fn build(self) -> ::std::result::Result<crate::types::ParameterListControl, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ParameterListControl {
            parameter_control_id: self.parameter_control_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "parameter_control_id",
                    "parameter_control_id was not specified but it is required when building ParameterListControl",
                )
            })?,
            title: self.title.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "title",
                    "title was not specified but it is required when building ParameterListControl",
                )
            })?,
            source_parameter_name: self.source_parameter_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source_parameter_name",
                    "source_parameter_name was not specified but it is required when building ParameterListControl",
                )
            })?,
            display_options: self.display_options,
            r#type: self.r#type,
            selectable_values: self.selectable_values,
            cascading_control_configuration: self.cascading_control_configuration,
        })
    }
}
