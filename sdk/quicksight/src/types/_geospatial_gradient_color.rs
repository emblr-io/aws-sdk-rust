// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The definition for a gradient color.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeospatialGradientColor {
    /// <p>A list of gradient step colors for the gradient.</p>
    pub step_colors: ::std::vec::Vec<crate::types::GeospatialGradientStepColor>,
    /// <p>The state of visibility for null data.</p>
    pub null_data_visibility: ::std::option::Option<crate::types::Visibility>,
    /// <p>The null data visualization settings.</p>
    pub null_data_settings: ::std::option::Option<crate::types::GeospatialNullDataSettings>,
    /// <p>The default opacity for the gradient color.</p>
    pub default_opacity: ::std::option::Option<f64>,
}
impl GeospatialGradientColor {
    /// <p>A list of gradient step colors for the gradient.</p>
    pub fn step_colors(&self) -> &[crate::types::GeospatialGradientStepColor] {
        use std::ops::Deref;
        self.step_colors.deref()
    }
    /// <p>The state of visibility for null data.</p>
    pub fn null_data_visibility(&self) -> ::std::option::Option<&crate::types::Visibility> {
        self.null_data_visibility.as_ref()
    }
    /// <p>The null data visualization settings.</p>
    pub fn null_data_settings(&self) -> ::std::option::Option<&crate::types::GeospatialNullDataSettings> {
        self.null_data_settings.as_ref()
    }
    /// <p>The default opacity for the gradient color.</p>
    pub fn default_opacity(&self) -> ::std::option::Option<f64> {
        self.default_opacity
    }
}
impl GeospatialGradientColor {
    /// Creates a new builder-style object to manufacture [`GeospatialGradientColor`](crate::types::GeospatialGradientColor).
    pub fn builder() -> crate::types::builders::GeospatialGradientColorBuilder {
        crate::types::builders::GeospatialGradientColorBuilder::default()
    }
}

/// A builder for [`GeospatialGradientColor`](crate::types::GeospatialGradientColor).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeospatialGradientColorBuilder {
    pub(crate) step_colors: ::std::option::Option<::std::vec::Vec<crate::types::GeospatialGradientStepColor>>,
    pub(crate) null_data_visibility: ::std::option::Option<crate::types::Visibility>,
    pub(crate) null_data_settings: ::std::option::Option<crate::types::GeospatialNullDataSettings>,
    pub(crate) default_opacity: ::std::option::Option<f64>,
}
impl GeospatialGradientColorBuilder {
    /// Appends an item to `step_colors`.
    ///
    /// To override the contents of this collection use [`set_step_colors`](Self::set_step_colors).
    ///
    /// <p>A list of gradient step colors for the gradient.</p>
    pub fn step_colors(mut self, input: crate::types::GeospatialGradientStepColor) -> Self {
        let mut v = self.step_colors.unwrap_or_default();
        v.push(input);
        self.step_colors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of gradient step colors for the gradient.</p>
    pub fn set_step_colors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GeospatialGradientStepColor>>) -> Self {
        self.step_colors = input;
        self
    }
    /// <p>A list of gradient step colors for the gradient.</p>
    pub fn get_step_colors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GeospatialGradientStepColor>> {
        &self.step_colors
    }
    /// <p>The state of visibility for null data.</p>
    pub fn null_data_visibility(mut self, input: crate::types::Visibility) -> Self {
        self.null_data_visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of visibility for null data.</p>
    pub fn set_null_data_visibility(mut self, input: ::std::option::Option<crate::types::Visibility>) -> Self {
        self.null_data_visibility = input;
        self
    }
    /// <p>The state of visibility for null data.</p>
    pub fn get_null_data_visibility(&self) -> &::std::option::Option<crate::types::Visibility> {
        &self.null_data_visibility
    }
    /// <p>The null data visualization settings.</p>
    pub fn null_data_settings(mut self, input: crate::types::GeospatialNullDataSettings) -> Self {
        self.null_data_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The null data visualization settings.</p>
    pub fn set_null_data_settings(mut self, input: ::std::option::Option<crate::types::GeospatialNullDataSettings>) -> Self {
        self.null_data_settings = input;
        self
    }
    /// <p>The null data visualization settings.</p>
    pub fn get_null_data_settings(&self) -> &::std::option::Option<crate::types::GeospatialNullDataSettings> {
        &self.null_data_settings
    }
    /// <p>The default opacity for the gradient color.</p>
    pub fn default_opacity(mut self, input: f64) -> Self {
        self.default_opacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default opacity for the gradient color.</p>
    pub fn set_default_opacity(mut self, input: ::std::option::Option<f64>) -> Self {
        self.default_opacity = input;
        self
    }
    /// <p>The default opacity for the gradient color.</p>
    pub fn get_default_opacity(&self) -> &::std::option::Option<f64> {
        &self.default_opacity
    }
    /// Consumes the builder and constructs a [`GeospatialGradientColor`](crate::types::GeospatialGradientColor).
    /// This method will fail if any of the following fields are not set:
    /// - [`step_colors`](crate::types::builders::GeospatialGradientColorBuilder::step_colors)
    pub fn build(self) -> ::std::result::Result<crate::types::GeospatialGradientColor, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GeospatialGradientColor {
            step_colors: self.step_colors.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "step_colors",
                    "step_colors was not specified but it is required when building GeospatialGradientColor",
                )
            })?,
            null_data_visibility: self.null_data_visibility,
            null_data_settings: self.null_data_settings,
            default_opacity: self.default_opacity,
        })
    }
}
