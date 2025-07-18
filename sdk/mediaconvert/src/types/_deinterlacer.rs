// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Settings for deinterlacer
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Deinterlacer {
    /// Only applies when you set Deinterlace mode to Deinterlace or Adaptive. Interpolate produces sharper pictures, while blend produces smoother motion. If your source file includes a ticker, such as a scrolling headline at the bottom of the frame: Choose Interpolate ticker or Blend ticker. To apply field doubling: Choose Linear interpolation. Note that Linear interpolation may introduce video artifacts into your output.
    pub algorithm: ::std::option::Option<crate::types::DeinterlaceAlgorithm>,
    /// - When set to NORMAL (default), the deinterlacer does not convert frames that are tagged in metadata as progressive. It will only convert those that are tagged as some other type. - When set to FORCE_ALL_FRAMES, the deinterlacer converts every frame to progressive - even those that are already tagged as progressive. Turn Force mode on only if there is a good chance that the metadata has tagged frames as progressive when they are not progressive. Do not turn on otherwise; processing frames that are already progressive into progressive will probably result in lower quality video.
    pub control: ::std::option::Option<crate::types::DeinterlacerControl>,
    /// Use Deinterlacer to choose how the service will do deinterlacing. Default is Deinterlace. - Deinterlace converts interlaced to progressive. - Inverse telecine converts Hard Telecine 29.97i to progressive 23.976p. - Adaptive auto-detects and converts to progressive.
    pub mode: ::std::option::Option<crate::types::DeinterlacerMode>,
}
impl Deinterlacer {
    /// Only applies when you set Deinterlace mode to Deinterlace or Adaptive. Interpolate produces sharper pictures, while blend produces smoother motion. If your source file includes a ticker, such as a scrolling headline at the bottom of the frame: Choose Interpolate ticker or Blend ticker. To apply field doubling: Choose Linear interpolation. Note that Linear interpolation may introduce video artifacts into your output.
    pub fn algorithm(&self) -> ::std::option::Option<&crate::types::DeinterlaceAlgorithm> {
        self.algorithm.as_ref()
    }
    /// - When set to NORMAL (default), the deinterlacer does not convert frames that are tagged in metadata as progressive. It will only convert those that are tagged as some other type. - When set to FORCE_ALL_FRAMES, the deinterlacer converts every frame to progressive - even those that are already tagged as progressive. Turn Force mode on only if there is a good chance that the metadata has tagged frames as progressive when they are not progressive. Do not turn on otherwise; processing frames that are already progressive into progressive will probably result in lower quality video.
    pub fn control(&self) -> ::std::option::Option<&crate::types::DeinterlacerControl> {
        self.control.as_ref()
    }
    /// Use Deinterlacer to choose how the service will do deinterlacing. Default is Deinterlace. - Deinterlace converts interlaced to progressive. - Inverse telecine converts Hard Telecine 29.97i to progressive 23.976p. - Adaptive auto-detects and converts to progressive.
    pub fn mode(&self) -> ::std::option::Option<&crate::types::DeinterlacerMode> {
        self.mode.as_ref()
    }
}
impl Deinterlacer {
    /// Creates a new builder-style object to manufacture [`Deinterlacer`](crate::types::Deinterlacer).
    pub fn builder() -> crate::types::builders::DeinterlacerBuilder {
        crate::types::builders::DeinterlacerBuilder::default()
    }
}

/// A builder for [`Deinterlacer`](crate::types::Deinterlacer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeinterlacerBuilder {
    pub(crate) algorithm: ::std::option::Option<crate::types::DeinterlaceAlgorithm>,
    pub(crate) control: ::std::option::Option<crate::types::DeinterlacerControl>,
    pub(crate) mode: ::std::option::Option<crate::types::DeinterlacerMode>,
}
impl DeinterlacerBuilder {
    /// Only applies when you set Deinterlace mode to Deinterlace or Adaptive. Interpolate produces sharper pictures, while blend produces smoother motion. If your source file includes a ticker, such as a scrolling headline at the bottom of the frame: Choose Interpolate ticker or Blend ticker. To apply field doubling: Choose Linear interpolation. Note that Linear interpolation may introduce video artifacts into your output.
    pub fn algorithm(mut self, input: crate::types::DeinterlaceAlgorithm) -> Self {
        self.algorithm = ::std::option::Option::Some(input);
        self
    }
    /// Only applies when you set Deinterlace mode to Deinterlace or Adaptive. Interpolate produces sharper pictures, while blend produces smoother motion. If your source file includes a ticker, such as a scrolling headline at the bottom of the frame: Choose Interpolate ticker or Blend ticker. To apply field doubling: Choose Linear interpolation. Note that Linear interpolation may introduce video artifacts into your output.
    pub fn set_algorithm(mut self, input: ::std::option::Option<crate::types::DeinterlaceAlgorithm>) -> Self {
        self.algorithm = input;
        self
    }
    /// Only applies when you set Deinterlace mode to Deinterlace or Adaptive. Interpolate produces sharper pictures, while blend produces smoother motion. If your source file includes a ticker, such as a scrolling headline at the bottom of the frame: Choose Interpolate ticker or Blend ticker. To apply field doubling: Choose Linear interpolation. Note that Linear interpolation may introduce video artifacts into your output.
    pub fn get_algorithm(&self) -> &::std::option::Option<crate::types::DeinterlaceAlgorithm> {
        &self.algorithm
    }
    /// - When set to NORMAL (default), the deinterlacer does not convert frames that are tagged in metadata as progressive. It will only convert those that are tagged as some other type. - When set to FORCE_ALL_FRAMES, the deinterlacer converts every frame to progressive - even those that are already tagged as progressive. Turn Force mode on only if there is a good chance that the metadata has tagged frames as progressive when they are not progressive. Do not turn on otherwise; processing frames that are already progressive into progressive will probably result in lower quality video.
    pub fn control(mut self, input: crate::types::DeinterlacerControl) -> Self {
        self.control = ::std::option::Option::Some(input);
        self
    }
    /// - When set to NORMAL (default), the deinterlacer does not convert frames that are tagged in metadata as progressive. It will only convert those that are tagged as some other type. - When set to FORCE_ALL_FRAMES, the deinterlacer converts every frame to progressive - even those that are already tagged as progressive. Turn Force mode on only if there is a good chance that the metadata has tagged frames as progressive when they are not progressive. Do not turn on otherwise; processing frames that are already progressive into progressive will probably result in lower quality video.
    pub fn set_control(mut self, input: ::std::option::Option<crate::types::DeinterlacerControl>) -> Self {
        self.control = input;
        self
    }
    /// - When set to NORMAL (default), the deinterlacer does not convert frames that are tagged in metadata as progressive. It will only convert those that are tagged as some other type. - When set to FORCE_ALL_FRAMES, the deinterlacer converts every frame to progressive - even those that are already tagged as progressive. Turn Force mode on only if there is a good chance that the metadata has tagged frames as progressive when they are not progressive. Do not turn on otherwise; processing frames that are already progressive into progressive will probably result in lower quality video.
    pub fn get_control(&self) -> &::std::option::Option<crate::types::DeinterlacerControl> {
        &self.control
    }
    /// Use Deinterlacer to choose how the service will do deinterlacing. Default is Deinterlace. - Deinterlace converts interlaced to progressive. - Inverse telecine converts Hard Telecine 29.97i to progressive 23.976p. - Adaptive auto-detects and converts to progressive.
    pub fn mode(mut self, input: crate::types::DeinterlacerMode) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// Use Deinterlacer to choose how the service will do deinterlacing. Default is Deinterlace. - Deinterlace converts interlaced to progressive. - Inverse telecine converts Hard Telecine 29.97i to progressive 23.976p. - Adaptive auto-detects and converts to progressive.
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::DeinterlacerMode>) -> Self {
        self.mode = input;
        self
    }
    /// Use Deinterlacer to choose how the service will do deinterlacing. Default is Deinterlace. - Deinterlace converts interlaced to progressive. - Inverse telecine converts Hard Telecine 29.97i to progressive 23.976p. - Adaptive auto-detects and converts to progressive.
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::DeinterlacerMode> {
        &self.mode
    }
    /// Consumes the builder and constructs a [`Deinterlacer`](crate::types::Deinterlacer).
    pub fn build(self) -> crate::types::Deinterlacer {
        crate::types::Deinterlacer {
            algorithm: self.algorithm,
            control: self.control,
            mode: self.mode,
        }
    }
}
