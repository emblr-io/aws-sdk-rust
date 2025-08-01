// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Dvb Sub Destination Settings
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DvbSubDestinationSettings {
    /// If no explicit xPosition or yPosition is provided, setting alignment to centered will place the captions at the bottom center of the output. Similarly, setting a left alignment will align captions to the bottom left of the output. If x and y positions are given in conjunction with the alignment parameter, the font will be justified (either left or centered) relative to those coordinates. Selecting "smart" justification will left-justify live subtitles and center-justify pre-recorded subtitles. This option is not valid for source captions that are STL or 608/embedded. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub alignment: ::std::option::Option<crate::types::DvbSubDestinationAlignment>,
    /// Specifies the color of the rectangle behind the captions. All burn-in and DVB-Sub font settings must match.
    pub background_color: ::std::option::Option<crate::types::DvbSubDestinationBackgroundColor>,
    /// Specifies the opacity of the background rectangle. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub background_opacity: ::std::option::Option<i32>,
    /// External font file used for caption burn-in. File extension must be 'ttf' or 'tte'. Although the user can select output fonts for many different types of input captions, embedded, STL and teletext sources use a strict grid system. Using external fonts with these caption sources could cause unexpected display of proportional fonts. All burn-in and DVB-Sub font settings must match.
    pub font: ::std::option::Option<crate::types::InputLocation>,
    /// Specifies the color of the burned-in captions. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub font_color: ::std::option::Option<crate::types::DvbSubDestinationFontColor>,
    /// Specifies the opacity of the burned-in captions. 255 is opaque; 0 is transparent. All burn-in and DVB-Sub font settings must match.
    pub font_opacity: ::std::option::Option<i32>,
    /// Font resolution in DPI (dots per inch); default is 96 dpi. All burn-in and DVB-Sub font settings must match.
    pub font_resolution: ::std::option::Option<i32>,
    /// When set to auto fontSize will scale depending on the size of the output. Giving a positive integer will specify the exact font size in points. All burn-in and DVB-Sub font settings must match.
    pub font_size: ::std::option::Option<::std::string::String>,
    /// Specifies font outline color. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub outline_color: ::std::option::Option<crate::types::DvbSubDestinationOutlineColor>,
    /// Specifies font outline size in pixels. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub outline_size: ::std::option::Option<i32>,
    /// Specifies the color of the shadow cast by the captions. All burn-in and DVB-Sub font settings must match.
    pub shadow_color: ::std::option::Option<crate::types::DvbSubDestinationShadowColor>,
    /// Specifies the opacity of the shadow. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub shadow_opacity: ::std::option::Option<i32>,
    /// Specifies the horizontal offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels to the left. All burn-in and DVB-Sub font settings must match.
    pub shadow_x_offset: ::std::option::Option<i32>,
    /// Specifies the vertical offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels above the text. All burn-in and DVB-Sub font settings must match.
    pub shadow_y_offset: ::std::option::Option<i32>,
    /// Controls whether a fixed grid size will be used to generate the output subtitles bitmap. Only applicable for Teletext inputs and DVB-Sub/Burn-in outputs.
    pub teletext_grid_control: ::std::option::Option<crate::types::DvbSubDestinationTeletextGridControl>,
    /// Specifies the horizontal position of the caption relative to the left side of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the left of the output. If no explicit xPosition is provided, the horizontal caption position will be determined by the alignment parameter. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub x_position: ::std::option::Option<i32>,
    /// Specifies the vertical position of the caption relative to the top of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the top of the output. If no explicit yPosition is provided, the caption will be positioned towards the bottom of the output. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub y_position: ::std::option::Option<i32>,
}
impl DvbSubDestinationSettings {
    /// If no explicit xPosition or yPosition is provided, setting alignment to centered will place the captions at the bottom center of the output. Similarly, setting a left alignment will align captions to the bottom left of the output. If x and y positions are given in conjunction with the alignment parameter, the font will be justified (either left or centered) relative to those coordinates. Selecting "smart" justification will left-justify live subtitles and center-justify pre-recorded subtitles. This option is not valid for source captions that are STL or 608/embedded. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn alignment(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationAlignment> {
        self.alignment.as_ref()
    }
    /// Specifies the color of the rectangle behind the captions. All burn-in and DVB-Sub font settings must match.
    pub fn background_color(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationBackgroundColor> {
        self.background_color.as_ref()
    }
    /// Specifies the opacity of the background rectangle. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn background_opacity(&self) -> ::std::option::Option<i32> {
        self.background_opacity
    }
    /// External font file used for caption burn-in. File extension must be 'ttf' or 'tte'. Although the user can select output fonts for many different types of input captions, embedded, STL and teletext sources use a strict grid system. Using external fonts with these caption sources could cause unexpected display of proportional fonts. All burn-in and DVB-Sub font settings must match.
    pub fn font(&self) -> ::std::option::Option<&crate::types::InputLocation> {
        self.font.as_ref()
    }
    /// Specifies the color of the burned-in captions. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn font_color(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationFontColor> {
        self.font_color.as_ref()
    }
    /// Specifies the opacity of the burned-in captions. 255 is opaque; 0 is transparent. All burn-in and DVB-Sub font settings must match.
    pub fn font_opacity(&self) -> ::std::option::Option<i32> {
        self.font_opacity
    }
    /// Font resolution in DPI (dots per inch); default is 96 dpi. All burn-in and DVB-Sub font settings must match.
    pub fn font_resolution(&self) -> ::std::option::Option<i32> {
        self.font_resolution
    }
    /// When set to auto fontSize will scale depending on the size of the output. Giving a positive integer will specify the exact font size in points. All burn-in and DVB-Sub font settings must match.
    pub fn font_size(&self) -> ::std::option::Option<&str> {
        self.font_size.as_deref()
    }
    /// Specifies font outline color. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn outline_color(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationOutlineColor> {
        self.outline_color.as_ref()
    }
    /// Specifies font outline size in pixels. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn outline_size(&self) -> ::std::option::Option<i32> {
        self.outline_size
    }
    /// Specifies the color of the shadow cast by the captions. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_color(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationShadowColor> {
        self.shadow_color.as_ref()
    }
    /// Specifies the opacity of the shadow. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn shadow_opacity(&self) -> ::std::option::Option<i32> {
        self.shadow_opacity
    }
    /// Specifies the horizontal offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels to the left. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_x_offset(&self) -> ::std::option::Option<i32> {
        self.shadow_x_offset
    }
    /// Specifies the vertical offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels above the text. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_y_offset(&self) -> ::std::option::Option<i32> {
        self.shadow_y_offset
    }
    /// Controls whether a fixed grid size will be used to generate the output subtitles bitmap. Only applicable for Teletext inputs and DVB-Sub/Burn-in outputs.
    pub fn teletext_grid_control(&self) -> ::std::option::Option<&crate::types::DvbSubDestinationTeletextGridControl> {
        self.teletext_grid_control.as_ref()
    }
    /// Specifies the horizontal position of the caption relative to the left side of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the left of the output. If no explicit xPosition is provided, the horizontal caption position will be determined by the alignment parameter. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn x_position(&self) -> ::std::option::Option<i32> {
        self.x_position
    }
    /// Specifies the vertical position of the caption relative to the top of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the top of the output. If no explicit yPosition is provided, the caption will be positioned towards the bottom of the output. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn y_position(&self) -> ::std::option::Option<i32> {
        self.y_position
    }
}
impl DvbSubDestinationSettings {
    /// Creates a new builder-style object to manufacture [`DvbSubDestinationSettings`](crate::types::DvbSubDestinationSettings).
    pub fn builder() -> crate::types::builders::DvbSubDestinationSettingsBuilder {
        crate::types::builders::DvbSubDestinationSettingsBuilder::default()
    }
}

/// A builder for [`DvbSubDestinationSettings`](crate::types::DvbSubDestinationSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DvbSubDestinationSettingsBuilder {
    pub(crate) alignment: ::std::option::Option<crate::types::DvbSubDestinationAlignment>,
    pub(crate) background_color: ::std::option::Option<crate::types::DvbSubDestinationBackgroundColor>,
    pub(crate) background_opacity: ::std::option::Option<i32>,
    pub(crate) font: ::std::option::Option<crate::types::InputLocation>,
    pub(crate) font_color: ::std::option::Option<crate::types::DvbSubDestinationFontColor>,
    pub(crate) font_opacity: ::std::option::Option<i32>,
    pub(crate) font_resolution: ::std::option::Option<i32>,
    pub(crate) font_size: ::std::option::Option<::std::string::String>,
    pub(crate) outline_color: ::std::option::Option<crate::types::DvbSubDestinationOutlineColor>,
    pub(crate) outline_size: ::std::option::Option<i32>,
    pub(crate) shadow_color: ::std::option::Option<crate::types::DvbSubDestinationShadowColor>,
    pub(crate) shadow_opacity: ::std::option::Option<i32>,
    pub(crate) shadow_x_offset: ::std::option::Option<i32>,
    pub(crate) shadow_y_offset: ::std::option::Option<i32>,
    pub(crate) teletext_grid_control: ::std::option::Option<crate::types::DvbSubDestinationTeletextGridControl>,
    pub(crate) x_position: ::std::option::Option<i32>,
    pub(crate) y_position: ::std::option::Option<i32>,
}
impl DvbSubDestinationSettingsBuilder {
    /// If no explicit xPosition or yPosition is provided, setting alignment to centered will place the captions at the bottom center of the output. Similarly, setting a left alignment will align captions to the bottom left of the output. If x and y positions are given in conjunction with the alignment parameter, the font will be justified (either left or centered) relative to those coordinates. Selecting "smart" justification will left-justify live subtitles and center-justify pre-recorded subtitles. This option is not valid for source captions that are STL or 608/embedded. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn alignment(mut self, input: crate::types::DvbSubDestinationAlignment) -> Self {
        self.alignment = ::std::option::Option::Some(input);
        self
    }
    /// If no explicit xPosition or yPosition is provided, setting alignment to centered will place the captions at the bottom center of the output. Similarly, setting a left alignment will align captions to the bottom left of the output. If x and y positions are given in conjunction with the alignment parameter, the font will be justified (either left or centered) relative to those coordinates. Selecting "smart" justification will left-justify live subtitles and center-justify pre-recorded subtitles. This option is not valid for source captions that are STL or 608/embedded. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_alignment(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationAlignment>) -> Self {
        self.alignment = input;
        self
    }
    /// If no explicit xPosition or yPosition is provided, setting alignment to centered will place the captions at the bottom center of the output. Similarly, setting a left alignment will align captions to the bottom left of the output. If x and y positions are given in conjunction with the alignment parameter, the font will be justified (either left or centered) relative to those coordinates. Selecting "smart" justification will left-justify live subtitles and center-justify pre-recorded subtitles. This option is not valid for source captions that are STL or 608/embedded. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_alignment(&self) -> &::std::option::Option<crate::types::DvbSubDestinationAlignment> {
        &self.alignment
    }
    /// Specifies the color of the rectangle behind the captions. All burn-in and DVB-Sub font settings must match.
    pub fn background_color(mut self, input: crate::types::DvbSubDestinationBackgroundColor) -> Self {
        self.background_color = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the color of the rectangle behind the captions. All burn-in and DVB-Sub font settings must match.
    pub fn set_background_color(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationBackgroundColor>) -> Self {
        self.background_color = input;
        self
    }
    /// Specifies the color of the rectangle behind the captions. All burn-in and DVB-Sub font settings must match.
    pub fn get_background_color(&self) -> &::std::option::Option<crate::types::DvbSubDestinationBackgroundColor> {
        &self.background_color
    }
    /// Specifies the opacity of the background rectangle. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn background_opacity(mut self, input: i32) -> Self {
        self.background_opacity = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the opacity of the background rectangle. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn set_background_opacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.background_opacity = input;
        self
    }
    /// Specifies the opacity of the background rectangle. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn get_background_opacity(&self) -> &::std::option::Option<i32> {
        &self.background_opacity
    }
    /// External font file used for caption burn-in. File extension must be 'ttf' or 'tte'. Although the user can select output fonts for many different types of input captions, embedded, STL and teletext sources use a strict grid system. Using external fonts with these caption sources could cause unexpected display of proportional fonts. All burn-in and DVB-Sub font settings must match.
    pub fn font(mut self, input: crate::types::InputLocation) -> Self {
        self.font = ::std::option::Option::Some(input);
        self
    }
    /// External font file used for caption burn-in. File extension must be 'ttf' or 'tte'. Although the user can select output fonts for many different types of input captions, embedded, STL and teletext sources use a strict grid system. Using external fonts with these caption sources could cause unexpected display of proportional fonts. All burn-in and DVB-Sub font settings must match.
    pub fn set_font(mut self, input: ::std::option::Option<crate::types::InputLocation>) -> Self {
        self.font = input;
        self
    }
    /// External font file used for caption burn-in. File extension must be 'ttf' or 'tte'. Although the user can select output fonts for many different types of input captions, embedded, STL and teletext sources use a strict grid system. Using external fonts with these caption sources could cause unexpected display of proportional fonts. All burn-in and DVB-Sub font settings must match.
    pub fn get_font(&self) -> &::std::option::Option<crate::types::InputLocation> {
        &self.font
    }
    /// Specifies the color of the burned-in captions. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn font_color(mut self, input: crate::types::DvbSubDestinationFontColor) -> Self {
        self.font_color = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the color of the burned-in captions. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_font_color(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationFontColor>) -> Self {
        self.font_color = input;
        self
    }
    /// Specifies the color of the burned-in captions. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_font_color(&self) -> &::std::option::Option<crate::types::DvbSubDestinationFontColor> {
        &self.font_color
    }
    /// Specifies the opacity of the burned-in captions. 255 is opaque; 0 is transparent. All burn-in and DVB-Sub font settings must match.
    pub fn font_opacity(mut self, input: i32) -> Self {
        self.font_opacity = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the opacity of the burned-in captions. 255 is opaque; 0 is transparent. All burn-in and DVB-Sub font settings must match.
    pub fn set_font_opacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.font_opacity = input;
        self
    }
    /// Specifies the opacity of the burned-in captions. 255 is opaque; 0 is transparent. All burn-in and DVB-Sub font settings must match.
    pub fn get_font_opacity(&self) -> &::std::option::Option<i32> {
        &self.font_opacity
    }
    /// Font resolution in DPI (dots per inch); default is 96 dpi. All burn-in and DVB-Sub font settings must match.
    pub fn font_resolution(mut self, input: i32) -> Self {
        self.font_resolution = ::std::option::Option::Some(input);
        self
    }
    /// Font resolution in DPI (dots per inch); default is 96 dpi. All burn-in and DVB-Sub font settings must match.
    pub fn set_font_resolution(mut self, input: ::std::option::Option<i32>) -> Self {
        self.font_resolution = input;
        self
    }
    /// Font resolution in DPI (dots per inch); default is 96 dpi. All burn-in and DVB-Sub font settings must match.
    pub fn get_font_resolution(&self) -> &::std::option::Option<i32> {
        &self.font_resolution
    }
    /// When set to auto fontSize will scale depending on the size of the output. Giving a positive integer will specify the exact font size in points. All burn-in and DVB-Sub font settings must match.
    pub fn font_size(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.font_size = ::std::option::Option::Some(input.into());
        self
    }
    /// When set to auto fontSize will scale depending on the size of the output. Giving a positive integer will specify the exact font size in points. All burn-in and DVB-Sub font settings must match.
    pub fn set_font_size(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.font_size = input;
        self
    }
    /// When set to auto fontSize will scale depending on the size of the output. Giving a positive integer will specify the exact font size in points. All burn-in and DVB-Sub font settings must match.
    pub fn get_font_size(&self) -> &::std::option::Option<::std::string::String> {
        &self.font_size
    }
    /// Specifies font outline color. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn outline_color(mut self, input: crate::types::DvbSubDestinationOutlineColor) -> Self {
        self.outline_color = ::std::option::Option::Some(input);
        self
    }
    /// Specifies font outline color. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_outline_color(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationOutlineColor>) -> Self {
        self.outline_color = input;
        self
    }
    /// Specifies font outline color. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_outline_color(&self) -> &::std::option::Option<crate::types::DvbSubDestinationOutlineColor> {
        &self.outline_color
    }
    /// Specifies font outline size in pixels. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn outline_size(mut self, input: i32) -> Self {
        self.outline_size = ::std::option::Option::Some(input);
        self
    }
    /// Specifies font outline size in pixels. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_outline_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.outline_size = input;
        self
    }
    /// Specifies font outline size in pixels. This option is not valid for source captions that are either 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_outline_size(&self) -> &::std::option::Option<i32> {
        &self.outline_size
    }
    /// Specifies the color of the shadow cast by the captions. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_color(mut self, input: crate::types::DvbSubDestinationShadowColor) -> Self {
        self.shadow_color = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the color of the shadow cast by the captions. All burn-in and DVB-Sub font settings must match.
    pub fn set_shadow_color(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationShadowColor>) -> Self {
        self.shadow_color = input;
        self
    }
    /// Specifies the color of the shadow cast by the captions. All burn-in and DVB-Sub font settings must match.
    pub fn get_shadow_color(&self) -> &::std::option::Option<crate::types::DvbSubDestinationShadowColor> {
        &self.shadow_color
    }
    /// Specifies the opacity of the shadow. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn shadow_opacity(mut self, input: i32) -> Self {
        self.shadow_opacity = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the opacity of the shadow. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn set_shadow_opacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.shadow_opacity = input;
        self
    }
    /// Specifies the opacity of the shadow. 255 is opaque; 0 is transparent. Leaving this parameter blank is equivalent to setting it to 0 (transparent). All burn-in and DVB-Sub font settings must match.
    pub fn get_shadow_opacity(&self) -> &::std::option::Option<i32> {
        &self.shadow_opacity
    }
    /// Specifies the horizontal offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels to the left. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_x_offset(mut self, input: i32) -> Self {
        self.shadow_x_offset = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the horizontal offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels to the left. All burn-in and DVB-Sub font settings must match.
    pub fn set_shadow_x_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.shadow_x_offset = input;
        self
    }
    /// Specifies the horizontal offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels to the left. All burn-in and DVB-Sub font settings must match.
    pub fn get_shadow_x_offset(&self) -> &::std::option::Option<i32> {
        &self.shadow_x_offset
    }
    /// Specifies the vertical offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels above the text. All burn-in and DVB-Sub font settings must match.
    pub fn shadow_y_offset(mut self, input: i32) -> Self {
        self.shadow_y_offset = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the vertical offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels above the text. All burn-in and DVB-Sub font settings must match.
    pub fn set_shadow_y_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.shadow_y_offset = input;
        self
    }
    /// Specifies the vertical offset of the shadow relative to the captions in pixels. A value of -2 would result in a shadow offset 2 pixels above the text. All burn-in and DVB-Sub font settings must match.
    pub fn get_shadow_y_offset(&self) -> &::std::option::Option<i32> {
        &self.shadow_y_offset
    }
    /// Controls whether a fixed grid size will be used to generate the output subtitles bitmap. Only applicable for Teletext inputs and DVB-Sub/Burn-in outputs.
    pub fn teletext_grid_control(mut self, input: crate::types::DvbSubDestinationTeletextGridControl) -> Self {
        self.teletext_grid_control = ::std::option::Option::Some(input);
        self
    }
    /// Controls whether a fixed grid size will be used to generate the output subtitles bitmap. Only applicable for Teletext inputs and DVB-Sub/Burn-in outputs.
    pub fn set_teletext_grid_control(mut self, input: ::std::option::Option<crate::types::DvbSubDestinationTeletextGridControl>) -> Self {
        self.teletext_grid_control = input;
        self
    }
    /// Controls whether a fixed grid size will be used to generate the output subtitles bitmap. Only applicable for Teletext inputs and DVB-Sub/Burn-in outputs.
    pub fn get_teletext_grid_control(&self) -> &::std::option::Option<crate::types::DvbSubDestinationTeletextGridControl> {
        &self.teletext_grid_control
    }
    /// Specifies the horizontal position of the caption relative to the left side of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the left of the output. If no explicit xPosition is provided, the horizontal caption position will be determined by the alignment parameter. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn x_position(mut self, input: i32) -> Self {
        self.x_position = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the horizontal position of the caption relative to the left side of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the left of the output. If no explicit xPosition is provided, the horizontal caption position will be determined by the alignment parameter. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_x_position(mut self, input: ::std::option::Option<i32>) -> Self {
        self.x_position = input;
        self
    }
    /// Specifies the horizontal position of the caption relative to the left side of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the left of the output. If no explicit xPosition is provided, the horizontal caption position will be determined by the alignment parameter. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_x_position(&self) -> &::std::option::Option<i32> {
        &self.x_position
    }
    /// Specifies the vertical position of the caption relative to the top of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the top of the output. If no explicit yPosition is provided, the caption will be positioned towards the bottom of the output. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn y_position(mut self, input: i32) -> Self {
        self.y_position = ::std::option::Option::Some(input);
        self
    }
    /// Specifies the vertical position of the caption relative to the top of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the top of the output. If no explicit yPosition is provided, the caption will be positioned towards the bottom of the output. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn set_y_position(mut self, input: ::std::option::Option<i32>) -> Self {
        self.y_position = input;
        self
    }
    /// Specifies the vertical position of the caption relative to the top of the output in pixels. A value of 10 would result in the captions starting 10 pixels from the top of the output. If no explicit yPosition is provided, the caption will be positioned towards the bottom of the output. This option is not valid for source captions that are STL, 608/embedded or teletext. These source settings are already pre-defined by the caption stream. All burn-in and DVB-Sub font settings must match.
    pub fn get_y_position(&self) -> &::std::option::Option<i32> {
        &self.y_position
    }
    /// Consumes the builder and constructs a [`DvbSubDestinationSettings`](crate::types::DvbSubDestinationSettings).
    pub fn build(self) -> crate::types::DvbSubDestinationSettings {
        crate::types::DvbSubDestinationSettings {
            alignment: self.alignment,
            background_color: self.background_color,
            background_opacity: self.background_opacity,
            font: self.font,
            font_color: self.font_color,
            font_opacity: self.font_opacity,
            font_resolution: self.font_resolution,
            font_size: self.font_size,
            outline_color: self.outline_color,
            outline_size: self.outline_size,
            shadow_color: self.shadow_color,
            shadow_opacity: self.shadow_opacity,
            shadow_x_offset: self.shadow_x_offset,
            shadow_y_offset: self.shadow_y_offset,
            teletext_grid_control: self.teletext_grid_control,
            x_position: self.x_position,
            y_position: self.y_position,
        }
    }
}
