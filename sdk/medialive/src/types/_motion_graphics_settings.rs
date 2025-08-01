// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Motion Graphics Settings
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MotionGraphicsSettings {
    /// Html Motion Graphics Settings
    pub html_motion_graphics_settings: ::std::option::Option<crate::types::HtmlMotionGraphicsSettings>,
}
impl MotionGraphicsSettings {
    /// Html Motion Graphics Settings
    pub fn html_motion_graphics_settings(&self) -> ::std::option::Option<&crate::types::HtmlMotionGraphicsSettings> {
        self.html_motion_graphics_settings.as_ref()
    }
}
impl MotionGraphicsSettings {
    /// Creates a new builder-style object to manufacture [`MotionGraphicsSettings`](crate::types::MotionGraphicsSettings).
    pub fn builder() -> crate::types::builders::MotionGraphicsSettingsBuilder {
        crate::types::builders::MotionGraphicsSettingsBuilder::default()
    }
}

/// A builder for [`MotionGraphicsSettings`](crate::types::MotionGraphicsSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MotionGraphicsSettingsBuilder {
    pub(crate) html_motion_graphics_settings: ::std::option::Option<crate::types::HtmlMotionGraphicsSettings>,
}
impl MotionGraphicsSettingsBuilder {
    /// Html Motion Graphics Settings
    pub fn html_motion_graphics_settings(mut self, input: crate::types::HtmlMotionGraphicsSettings) -> Self {
        self.html_motion_graphics_settings = ::std::option::Option::Some(input);
        self
    }
    /// Html Motion Graphics Settings
    pub fn set_html_motion_graphics_settings(mut self, input: ::std::option::Option<crate::types::HtmlMotionGraphicsSettings>) -> Self {
        self.html_motion_graphics_settings = input;
        self
    }
    /// Html Motion Graphics Settings
    pub fn get_html_motion_graphics_settings(&self) -> &::std::option::Option<crate::types::HtmlMotionGraphicsSettings> {
        &self.html_motion_graphics_settings
    }
    /// Consumes the builder and constructs a [`MotionGraphicsSettings`](crate::types::MotionGraphicsSettings).
    pub fn build(self) -> crate::types::MotionGraphicsSettings {
        crate::types::MotionGraphicsSettings {
            html_motion_graphics_settings: self.html_motion_graphics_settings,
        }
    }
}
