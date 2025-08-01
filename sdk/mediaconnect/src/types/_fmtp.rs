// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A set of parameters that define the media stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Fmtp {
    /// <p>The format of the audio channel.</p>
    pub channel_order: ::std::option::Option<::std::string::String>,
    /// <p>The format used for the representation of color.</p>
    pub colorimetry: ::std::option::Option<crate::types::Colorimetry>,
    /// <p>The frame rate for the video stream, in frames/second. For example: 60000/1001.</p>
    pub exact_framerate: ::std::option::Option<::std::string::String>,
    /// <p>The pixel aspect ratio (PAR) of the video.</p>
    pub par: ::std::option::Option<::std::string::String>,
    /// <p>The encoding range of the video.</p>
    pub range: ::std::option::Option<crate::types::Range>,
    /// <p>The type of compression that was used to smooth the video’s appearance.</p>
    pub scan_mode: ::std::option::Option<crate::types::ScanMode>,
    /// <p>The transfer characteristic system (TCS) that is used in the video.</p>
    pub tcs: ::std::option::Option<crate::types::Tcs>,
}
impl Fmtp {
    /// <p>The format of the audio channel.</p>
    pub fn channel_order(&self) -> ::std::option::Option<&str> {
        self.channel_order.as_deref()
    }
    /// <p>The format used for the representation of color.</p>
    pub fn colorimetry(&self) -> ::std::option::Option<&crate::types::Colorimetry> {
        self.colorimetry.as_ref()
    }
    /// <p>The frame rate for the video stream, in frames/second. For example: 60000/1001.</p>
    pub fn exact_framerate(&self) -> ::std::option::Option<&str> {
        self.exact_framerate.as_deref()
    }
    /// <p>The pixel aspect ratio (PAR) of the video.</p>
    pub fn par(&self) -> ::std::option::Option<&str> {
        self.par.as_deref()
    }
    /// <p>The encoding range of the video.</p>
    pub fn range(&self) -> ::std::option::Option<&crate::types::Range> {
        self.range.as_ref()
    }
    /// <p>The type of compression that was used to smooth the video’s appearance.</p>
    pub fn scan_mode(&self) -> ::std::option::Option<&crate::types::ScanMode> {
        self.scan_mode.as_ref()
    }
    /// <p>The transfer characteristic system (TCS) that is used in the video.</p>
    pub fn tcs(&self) -> ::std::option::Option<&crate::types::Tcs> {
        self.tcs.as_ref()
    }
}
impl Fmtp {
    /// Creates a new builder-style object to manufacture [`Fmtp`](crate::types::Fmtp).
    pub fn builder() -> crate::types::builders::FmtpBuilder {
        crate::types::builders::FmtpBuilder::default()
    }
}

/// A builder for [`Fmtp`](crate::types::Fmtp).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FmtpBuilder {
    pub(crate) channel_order: ::std::option::Option<::std::string::String>,
    pub(crate) colorimetry: ::std::option::Option<crate::types::Colorimetry>,
    pub(crate) exact_framerate: ::std::option::Option<::std::string::String>,
    pub(crate) par: ::std::option::Option<::std::string::String>,
    pub(crate) range: ::std::option::Option<crate::types::Range>,
    pub(crate) scan_mode: ::std::option::Option<crate::types::ScanMode>,
    pub(crate) tcs: ::std::option::Option<crate::types::Tcs>,
}
impl FmtpBuilder {
    /// <p>The format of the audio channel.</p>
    pub fn channel_order(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_order = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format of the audio channel.</p>
    pub fn set_channel_order(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_order = input;
        self
    }
    /// <p>The format of the audio channel.</p>
    pub fn get_channel_order(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_order
    }
    /// <p>The format used for the representation of color.</p>
    pub fn colorimetry(mut self, input: crate::types::Colorimetry) -> Self {
        self.colorimetry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format used for the representation of color.</p>
    pub fn set_colorimetry(mut self, input: ::std::option::Option<crate::types::Colorimetry>) -> Self {
        self.colorimetry = input;
        self
    }
    /// <p>The format used for the representation of color.</p>
    pub fn get_colorimetry(&self) -> &::std::option::Option<crate::types::Colorimetry> {
        &self.colorimetry
    }
    /// <p>The frame rate for the video stream, in frames/second. For example: 60000/1001.</p>
    pub fn exact_framerate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exact_framerate = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The frame rate for the video stream, in frames/second. For example: 60000/1001.</p>
    pub fn set_exact_framerate(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exact_framerate = input;
        self
    }
    /// <p>The frame rate for the video stream, in frames/second. For example: 60000/1001.</p>
    pub fn get_exact_framerate(&self) -> &::std::option::Option<::std::string::String> {
        &self.exact_framerate
    }
    /// <p>The pixel aspect ratio (PAR) of the video.</p>
    pub fn par(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.par = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pixel aspect ratio (PAR) of the video.</p>
    pub fn set_par(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.par = input;
        self
    }
    /// <p>The pixel aspect ratio (PAR) of the video.</p>
    pub fn get_par(&self) -> &::std::option::Option<::std::string::String> {
        &self.par
    }
    /// <p>The encoding range of the video.</p>
    pub fn range(mut self, input: crate::types::Range) -> Self {
        self.range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encoding range of the video.</p>
    pub fn set_range(mut self, input: ::std::option::Option<crate::types::Range>) -> Self {
        self.range = input;
        self
    }
    /// <p>The encoding range of the video.</p>
    pub fn get_range(&self) -> &::std::option::Option<crate::types::Range> {
        &self.range
    }
    /// <p>The type of compression that was used to smooth the video’s appearance.</p>
    pub fn scan_mode(mut self, input: crate::types::ScanMode) -> Self {
        self.scan_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of compression that was used to smooth the video’s appearance.</p>
    pub fn set_scan_mode(mut self, input: ::std::option::Option<crate::types::ScanMode>) -> Self {
        self.scan_mode = input;
        self
    }
    /// <p>The type of compression that was used to smooth the video’s appearance.</p>
    pub fn get_scan_mode(&self) -> &::std::option::Option<crate::types::ScanMode> {
        &self.scan_mode
    }
    /// <p>The transfer characteristic system (TCS) that is used in the video.</p>
    pub fn tcs(mut self, input: crate::types::Tcs) -> Self {
        self.tcs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The transfer characteristic system (TCS) that is used in the video.</p>
    pub fn set_tcs(mut self, input: ::std::option::Option<crate::types::Tcs>) -> Self {
        self.tcs = input;
        self
    }
    /// <p>The transfer characteristic system (TCS) that is used in the video.</p>
    pub fn get_tcs(&self) -> &::std::option::Option<crate::types::Tcs> {
        &self.tcs
    }
    /// Consumes the builder and constructs a [`Fmtp`](crate::types::Fmtp).
    pub fn build(self) -> crate::types::Fmtp {
        crate::types::Fmtp {
            channel_order: self.channel_order,
            colorimetry: self.colorimetry,
            exact_framerate: self.exact_framerate,
            par: self.par,
            range: self.range,
            scan_mode: self.scan_mode,
            tcs: self.tcs,
        }
    }
}
