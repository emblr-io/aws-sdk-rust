// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An image that is located on a sheet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SheetImage {
    /// <p>The ID of the sheet image.</p>
    pub sheet_image_id: ::std::string::String,
    /// <p>The source of the image.</p>
    pub source: ::std::option::Option<crate::types::SheetImageSource>,
    /// <p>Determines how the image is scaled.</p>
    pub scaling: ::std::option::Option<crate::types::SheetImageScalingConfiguration>,
    /// <p>The tooltip to be shown when hovering over the image.</p>
    pub tooltip: ::std::option::Option<crate::types::SheetImageTooltipConfiguration>,
    /// <p>The alt text for the image.</p>
    pub image_content_alt_text: ::std::option::Option<::std::string::String>,
    /// <p>The general image interactions setup for an image.</p>
    pub interactions: ::std::option::Option<crate::types::ImageInteractionOptions>,
    /// <p>A list of custom actions that are configured for an image.</p>
    pub actions: ::std::option::Option<::std::vec::Vec<crate::types::ImageCustomAction>>,
}
impl SheetImage {
    /// <p>The ID of the sheet image.</p>
    pub fn sheet_image_id(&self) -> &str {
        use std::ops::Deref;
        self.sheet_image_id.deref()
    }
    /// <p>The source of the image.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::SheetImageSource> {
        self.source.as_ref()
    }
    /// <p>Determines how the image is scaled.</p>
    pub fn scaling(&self) -> ::std::option::Option<&crate::types::SheetImageScalingConfiguration> {
        self.scaling.as_ref()
    }
    /// <p>The tooltip to be shown when hovering over the image.</p>
    pub fn tooltip(&self) -> ::std::option::Option<&crate::types::SheetImageTooltipConfiguration> {
        self.tooltip.as_ref()
    }
    /// <p>The alt text for the image.</p>
    pub fn image_content_alt_text(&self) -> ::std::option::Option<&str> {
        self.image_content_alt_text.as_deref()
    }
    /// <p>The general image interactions setup for an image.</p>
    pub fn interactions(&self) -> ::std::option::Option<&crate::types::ImageInteractionOptions> {
        self.interactions.as_ref()
    }
    /// <p>A list of custom actions that are configured for an image.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions.is_none()`.
    pub fn actions(&self) -> &[crate::types::ImageCustomAction] {
        self.actions.as_deref().unwrap_or_default()
    }
}
impl SheetImage {
    /// Creates a new builder-style object to manufacture [`SheetImage`](crate::types::SheetImage).
    pub fn builder() -> crate::types::builders::SheetImageBuilder {
        crate::types::builders::SheetImageBuilder::default()
    }
}

/// A builder for [`SheetImage`](crate::types::SheetImage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SheetImageBuilder {
    pub(crate) sheet_image_id: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<crate::types::SheetImageSource>,
    pub(crate) scaling: ::std::option::Option<crate::types::SheetImageScalingConfiguration>,
    pub(crate) tooltip: ::std::option::Option<crate::types::SheetImageTooltipConfiguration>,
    pub(crate) image_content_alt_text: ::std::option::Option<::std::string::String>,
    pub(crate) interactions: ::std::option::Option<crate::types::ImageInteractionOptions>,
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<crate::types::ImageCustomAction>>,
}
impl SheetImageBuilder {
    /// <p>The ID of the sheet image.</p>
    /// This field is required.
    pub fn sheet_image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sheet_image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the sheet image.</p>
    pub fn set_sheet_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sheet_image_id = input;
        self
    }
    /// <p>The ID of the sheet image.</p>
    pub fn get_sheet_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sheet_image_id
    }
    /// <p>The source of the image.</p>
    /// This field is required.
    pub fn source(mut self, input: crate::types::SheetImageSource) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source of the image.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::SheetImageSource>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source of the image.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::SheetImageSource> {
        &self.source
    }
    /// <p>Determines how the image is scaled.</p>
    pub fn scaling(mut self, input: crate::types::SheetImageScalingConfiguration) -> Self {
        self.scaling = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines how the image is scaled.</p>
    pub fn set_scaling(mut self, input: ::std::option::Option<crate::types::SheetImageScalingConfiguration>) -> Self {
        self.scaling = input;
        self
    }
    /// <p>Determines how the image is scaled.</p>
    pub fn get_scaling(&self) -> &::std::option::Option<crate::types::SheetImageScalingConfiguration> {
        &self.scaling
    }
    /// <p>The tooltip to be shown when hovering over the image.</p>
    pub fn tooltip(mut self, input: crate::types::SheetImageTooltipConfiguration) -> Self {
        self.tooltip = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tooltip to be shown when hovering over the image.</p>
    pub fn set_tooltip(mut self, input: ::std::option::Option<crate::types::SheetImageTooltipConfiguration>) -> Self {
        self.tooltip = input;
        self
    }
    /// <p>The tooltip to be shown when hovering over the image.</p>
    pub fn get_tooltip(&self) -> &::std::option::Option<crate::types::SheetImageTooltipConfiguration> {
        &self.tooltip
    }
    /// <p>The alt text for the image.</p>
    pub fn image_content_alt_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_content_alt_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alt text for the image.</p>
    pub fn set_image_content_alt_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_content_alt_text = input;
        self
    }
    /// <p>The alt text for the image.</p>
    pub fn get_image_content_alt_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_content_alt_text
    }
    /// <p>The general image interactions setup for an image.</p>
    pub fn interactions(mut self, input: crate::types::ImageInteractionOptions) -> Self {
        self.interactions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The general image interactions setup for an image.</p>
    pub fn set_interactions(mut self, input: ::std::option::Option<crate::types::ImageInteractionOptions>) -> Self {
        self.interactions = input;
        self
    }
    /// <p>The general image interactions setup for an image.</p>
    pub fn get_interactions(&self) -> &::std::option::Option<crate::types::ImageInteractionOptions> {
        &self.interactions
    }
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>A list of custom actions that are configured for an image.</p>
    pub fn actions(mut self, input: crate::types::ImageCustomAction) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input);
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of custom actions that are configured for an image.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImageCustomAction>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>A list of custom actions that are configured for an image.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImageCustomAction>> {
        &self.actions
    }
    /// Consumes the builder and constructs a [`SheetImage`](crate::types::SheetImage).
    /// This method will fail if any of the following fields are not set:
    /// - [`sheet_image_id`](crate::types::builders::SheetImageBuilder::sheet_image_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SheetImage, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SheetImage {
            sheet_image_id: self.sheet_image_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sheet_image_id",
                    "sheet_image_id was not specified but it is required when building SheetImage",
                )
            })?,
            source: self.source,
            scaling: self.scaling,
            tooltip: self.tooltip,
            image_content_alt_text: self.image_content_alt_text,
            interactions: self.interactions,
            actions: self.actions,
        })
    }
}
