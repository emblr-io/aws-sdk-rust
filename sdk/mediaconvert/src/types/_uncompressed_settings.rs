// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Required when you set Codec, under VideoDescription&gt;CodecSettings to the value UNCOMPRESSED.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UncompressedSettings {
    /// The four character code for the uncompressed video.
    pub fourcc: ::std::option::Option<crate::types::UncompressedFourcc>,
    /// Use the Framerate setting to specify the frame rate for this output. If you want to keep the same frame rate as the input video, choose Follow source. If you want to do frame rate conversion, choose a frame rate from the dropdown list or choose Custom. The framerates shown in the dropdown list are decimal approximations of fractions. If you choose Custom, specify your frame rate as a fraction.
    pub framerate_control: ::std::option::Option<crate::types::UncompressedFramerateControl>,
    /// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
    pub framerate_conversion_algorithm: ::std::option::Option<crate::types::UncompressedFramerateConversionAlgorithm>,
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateDenominator to specify the denominator of this fraction. In this example, use 1001 for the value of FramerateDenominator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub framerate_denominator: ::std::option::Option<i32>,
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateNumerator to specify the numerator of this fraction. In this example, use 24000 for the value of FramerateNumerator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub framerate_numerator: ::std::option::Option<i32>,
    /// Optional. Choose the scan line type for this output. If you don't specify a value, MediaConvert will create a progressive output.
    pub interlace_mode: ::std::option::Option<crate::types::UncompressedInterlaceMode>,
    /// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
    pub scan_type_conversion_mode: ::std::option::Option<crate::types::UncompressedScanTypeConversionMode>,
    /// Ignore this setting unless your input frame rate is 23.976 or 24 frames per second (fps). Enable slow PAL to create a 25 fps output by relabeling the video frames and resampling your audio. Note that enabling this setting will slightly reduce the duration of your video. Related settings: You must also set Framerate to 25.
    pub slow_pal: ::std::option::Option<crate::types::UncompressedSlowPal>,
    /// When you do frame rate conversion from 23.976 frames per second (fps) to 29.97 fps, and your output scan type is interlaced, you can optionally enable hard telecine to create a smoother picture. When you keep the default value, None, MediaConvert does a standard frame rate conversion to 29.97 without doing anything with the field polarity to create a smoother picture.
    pub telecine: ::std::option::Option<crate::types::UncompressedTelecine>,
}
impl UncompressedSettings {
    /// The four character code for the uncompressed video.
    pub fn fourcc(&self) -> ::std::option::Option<&crate::types::UncompressedFourcc> {
        self.fourcc.as_ref()
    }
    /// Use the Framerate setting to specify the frame rate for this output. If you want to keep the same frame rate as the input video, choose Follow source. If you want to do frame rate conversion, choose a frame rate from the dropdown list or choose Custom. The framerates shown in the dropdown list are decimal approximations of fractions. If you choose Custom, specify your frame rate as a fraction.
    pub fn framerate_control(&self) -> ::std::option::Option<&crate::types::UncompressedFramerateControl> {
        self.framerate_control.as_ref()
    }
    /// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
    pub fn framerate_conversion_algorithm(&self) -> ::std::option::Option<&crate::types::UncompressedFramerateConversionAlgorithm> {
        self.framerate_conversion_algorithm.as_ref()
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateDenominator to specify the denominator of this fraction. In this example, use 1001 for the value of FramerateDenominator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn framerate_denominator(&self) -> ::std::option::Option<i32> {
        self.framerate_denominator
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateNumerator to specify the numerator of this fraction. In this example, use 24000 for the value of FramerateNumerator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn framerate_numerator(&self) -> ::std::option::Option<i32> {
        self.framerate_numerator
    }
    /// Optional. Choose the scan line type for this output. If you don't specify a value, MediaConvert will create a progressive output.
    pub fn interlace_mode(&self) -> ::std::option::Option<&crate::types::UncompressedInterlaceMode> {
        self.interlace_mode.as_ref()
    }
    /// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
    pub fn scan_type_conversion_mode(&self) -> ::std::option::Option<&crate::types::UncompressedScanTypeConversionMode> {
        self.scan_type_conversion_mode.as_ref()
    }
    /// Ignore this setting unless your input frame rate is 23.976 or 24 frames per second (fps). Enable slow PAL to create a 25 fps output by relabeling the video frames and resampling your audio. Note that enabling this setting will slightly reduce the duration of your video. Related settings: You must also set Framerate to 25.
    pub fn slow_pal(&self) -> ::std::option::Option<&crate::types::UncompressedSlowPal> {
        self.slow_pal.as_ref()
    }
    /// When you do frame rate conversion from 23.976 frames per second (fps) to 29.97 fps, and your output scan type is interlaced, you can optionally enable hard telecine to create a smoother picture. When you keep the default value, None, MediaConvert does a standard frame rate conversion to 29.97 without doing anything with the field polarity to create a smoother picture.
    pub fn telecine(&self) -> ::std::option::Option<&crate::types::UncompressedTelecine> {
        self.telecine.as_ref()
    }
}
impl UncompressedSettings {
    /// Creates a new builder-style object to manufacture [`UncompressedSettings`](crate::types::UncompressedSettings).
    pub fn builder() -> crate::types::builders::UncompressedSettingsBuilder {
        crate::types::builders::UncompressedSettingsBuilder::default()
    }
}

/// A builder for [`UncompressedSettings`](crate::types::UncompressedSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UncompressedSettingsBuilder {
    pub(crate) fourcc: ::std::option::Option<crate::types::UncompressedFourcc>,
    pub(crate) framerate_control: ::std::option::Option<crate::types::UncompressedFramerateControl>,
    pub(crate) framerate_conversion_algorithm: ::std::option::Option<crate::types::UncompressedFramerateConversionAlgorithm>,
    pub(crate) framerate_denominator: ::std::option::Option<i32>,
    pub(crate) framerate_numerator: ::std::option::Option<i32>,
    pub(crate) interlace_mode: ::std::option::Option<crate::types::UncompressedInterlaceMode>,
    pub(crate) scan_type_conversion_mode: ::std::option::Option<crate::types::UncompressedScanTypeConversionMode>,
    pub(crate) slow_pal: ::std::option::Option<crate::types::UncompressedSlowPal>,
    pub(crate) telecine: ::std::option::Option<crate::types::UncompressedTelecine>,
}
impl UncompressedSettingsBuilder {
    /// The four character code for the uncompressed video.
    pub fn fourcc(mut self, input: crate::types::UncompressedFourcc) -> Self {
        self.fourcc = ::std::option::Option::Some(input);
        self
    }
    /// The four character code for the uncompressed video.
    pub fn set_fourcc(mut self, input: ::std::option::Option<crate::types::UncompressedFourcc>) -> Self {
        self.fourcc = input;
        self
    }
    /// The four character code for the uncompressed video.
    pub fn get_fourcc(&self) -> &::std::option::Option<crate::types::UncompressedFourcc> {
        &self.fourcc
    }
    /// Use the Framerate setting to specify the frame rate for this output. If you want to keep the same frame rate as the input video, choose Follow source. If you want to do frame rate conversion, choose a frame rate from the dropdown list or choose Custom. The framerates shown in the dropdown list are decimal approximations of fractions. If you choose Custom, specify your frame rate as a fraction.
    pub fn framerate_control(mut self, input: crate::types::UncompressedFramerateControl) -> Self {
        self.framerate_control = ::std::option::Option::Some(input);
        self
    }
    /// Use the Framerate setting to specify the frame rate for this output. If you want to keep the same frame rate as the input video, choose Follow source. If you want to do frame rate conversion, choose a frame rate from the dropdown list or choose Custom. The framerates shown in the dropdown list are decimal approximations of fractions. If you choose Custom, specify your frame rate as a fraction.
    pub fn set_framerate_control(mut self, input: ::std::option::Option<crate::types::UncompressedFramerateControl>) -> Self {
        self.framerate_control = input;
        self
    }
    /// Use the Framerate setting to specify the frame rate for this output. If you want to keep the same frame rate as the input video, choose Follow source. If you want to do frame rate conversion, choose a frame rate from the dropdown list or choose Custom. The framerates shown in the dropdown list are decimal approximations of fractions. If you choose Custom, specify your frame rate as a fraction.
    pub fn get_framerate_control(&self) -> &::std::option::Option<crate::types::UncompressedFramerateControl> {
        &self.framerate_control
    }
    /// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
    pub fn framerate_conversion_algorithm(mut self, input: crate::types::UncompressedFramerateConversionAlgorithm) -> Self {
        self.framerate_conversion_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
    pub fn set_framerate_conversion_algorithm(
        mut self,
        input: ::std::option::Option<crate::types::UncompressedFramerateConversionAlgorithm>,
    ) -> Self {
        self.framerate_conversion_algorithm = input;
        self
    }
    /// Choose the method that you want MediaConvert to use when increasing or decreasing your video's frame rate. For numerically simple conversions, such as 60 fps to 30 fps: We recommend that you keep the default value, Drop duplicate. For numerically complex conversions, to avoid stutter: Choose Interpolate. This results in a smooth picture, but might introduce undesirable video artifacts. For complex frame rate conversions, especially if your source video has already been converted from its original cadence: Choose FrameFormer to do motion-compensated interpolation. FrameFormer uses the best conversion method frame by frame. Note that using FrameFormer increases the transcoding time and incurs a significant add-on cost. When you choose FrameFormer, your input video resolution must be at least 128x96. To create an output with the same number of frames as your input: Choose Maintain frame count. When you do, MediaConvert will not drop, interpolate, add, or otherwise change the frame count from your input to your output. Note that since the frame count is maintained, the duration of your output will become shorter at higher frame rates and longer at lower frame rates.
    pub fn get_framerate_conversion_algorithm(&self) -> &::std::option::Option<crate::types::UncompressedFramerateConversionAlgorithm> {
        &self.framerate_conversion_algorithm
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateDenominator to specify the denominator of this fraction. In this example, use 1001 for the value of FramerateDenominator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn framerate_denominator(mut self, input: i32) -> Self {
        self.framerate_denominator = ::std::option::Option::Some(input);
        self
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateDenominator to specify the denominator of this fraction. In this example, use 1001 for the value of FramerateDenominator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn set_framerate_denominator(mut self, input: ::std::option::Option<i32>) -> Self {
        self.framerate_denominator = input;
        self
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateDenominator to specify the denominator of this fraction. In this example, use 1001 for the value of FramerateDenominator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn get_framerate_denominator(&self) -> &::std::option::Option<i32> {
        &self.framerate_denominator
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateNumerator to specify the numerator of this fraction. In this example, use 24000 for the value of FramerateNumerator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn framerate_numerator(mut self, input: i32) -> Self {
        self.framerate_numerator = ::std::option::Option::Some(input);
        self
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateNumerator to specify the numerator of this fraction. In this example, use 24000 for the value of FramerateNumerator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn set_framerate_numerator(mut self, input: ::std::option::Option<i32>) -> Self {
        self.framerate_numerator = input;
        self
    }
    /// When you use the API for transcode jobs that use frame rate conversion, specify the frame rate as a fraction. For example, 24000 / 1001 = 23.976 fps. Use FramerateNumerator to specify the numerator of this fraction. In this example, use 24000 for the value of FramerateNumerator. When you use the console for transcode jobs that use frame rate conversion, provide the value as a decimal number for Framerate. In this example, specify 23.976.
    pub fn get_framerate_numerator(&self) -> &::std::option::Option<i32> {
        &self.framerate_numerator
    }
    /// Optional. Choose the scan line type for this output. If you don't specify a value, MediaConvert will create a progressive output.
    pub fn interlace_mode(mut self, input: crate::types::UncompressedInterlaceMode) -> Self {
        self.interlace_mode = ::std::option::Option::Some(input);
        self
    }
    /// Optional. Choose the scan line type for this output. If you don't specify a value, MediaConvert will create a progressive output.
    pub fn set_interlace_mode(mut self, input: ::std::option::Option<crate::types::UncompressedInterlaceMode>) -> Self {
        self.interlace_mode = input;
        self
    }
    /// Optional. Choose the scan line type for this output. If you don't specify a value, MediaConvert will create a progressive output.
    pub fn get_interlace_mode(&self) -> &::std::option::Option<crate::types::UncompressedInterlaceMode> {
        &self.interlace_mode
    }
    /// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
    pub fn scan_type_conversion_mode(mut self, input: crate::types::UncompressedScanTypeConversionMode) -> Self {
        self.scan_type_conversion_mode = ::std::option::Option::Some(input);
        self
    }
    /// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
    pub fn set_scan_type_conversion_mode(mut self, input: ::std::option::Option<crate::types::UncompressedScanTypeConversionMode>) -> Self {
        self.scan_type_conversion_mode = input;
        self
    }
    /// Use this setting for interlaced outputs, when your output frame rate is half of your input frame rate. In this situation, choose Optimized interlacing to create a better quality interlaced output. In this case, each progressive frame from the input corresponds to an interlaced field in the output. Keep the default value, Basic interlacing, for all other output frame rates. With basic interlacing, MediaConvert performs any frame rate conversion first and then interlaces the frames. When you choose Optimized interlacing and you set your output frame rate to a value that isn't suitable for optimized interlacing, MediaConvert automatically falls back to basic interlacing. Required settings: To use optimized interlacing, you must set Telecine to None or Soft. You can't use optimized interlacing for hard telecine outputs. You must also set Interlace mode to a value other than Progressive.
    pub fn get_scan_type_conversion_mode(&self) -> &::std::option::Option<crate::types::UncompressedScanTypeConversionMode> {
        &self.scan_type_conversion_mode
    }
    /// Ignore this setting unless your input frame rate is 23.976 or 24 frames per second (fps). Enable slow PAL to create a 25 fps output by relabeling the video frames and resampling your audio. Note that enabling this setting will slightly reduce the duration of your video. Related settings: You must also set Framerate to 25.
    pub fn slow_pal(mut self, input: crate::types::UncompressedSlowPal) -> Self {
        self.slow_pal = ::std::option::Option::Some(input);
        self
    }
    /// Ignore this setting unless your input frame rate is 23.976 or 24 frames per second (fps). Enable slow PAL to create a 25 fps output by relabeling the video frames and resampling your audio. Note that enabling this setting will slightly reduce the duration of your video. Related settings: You must also set Framerate to 25.
    pub fn set_slow_pal(mut self, input: ::std::option::Option<crate::types::UncompressedSlowPal>) -> Self {
        self.slow_pal = input;
        self
    }
    /// Ignore this setting unless your input frame rate is 23.976 or 24 frames per second (fps). Enable slow PAL to create a 25 fps output by relabeling the video frames and resampling your audio. Note that enabling this setting will slightly reduce the duration of your video. Related settings: You must also set Framerate to 25.
    pub fn get_slow_pal(&self) -> &::std::option::Option<crate::types::UncompressedSlowPal> {
        &self.slow_pal
    }
    /// When you do frame rate conversion from 23.976 frames per second (fps) to 29.97 fps, and your output scan type is interlaced, you can optionally enable hard telecine to create a smoother picture. When you keep the default value, None, MediaConvert does a standard frame rate conversion to 29.97 without doing anything with the field polarity to create a smoother picture.
    pub fn telecine(mut self, input: crate::types::UncompressedTelecine) -> Self {
        self.telecine = ::std::option::Option::Some(input);
        self
    }
    /// When you do frame rate conversion from 23.976 frames per second (fps) to 29.97 fps, and your output scan type is interlaced, you can optionally enable hard telecine to create a smoother picture. When you keep the default value, None, MediaConvert does a standard frame rate conversion to 29.97 without doing anything with the field polarity to create a smoother picture.
    pub fn set_telecine(mut self, input: ::std::option::Option<crate::types::UncompressedTelecine>) -> Self {
        self.telecine = input;
        self
    }
    /// When you do frame rate conversion from 23.976 frames per second (fps) to 29.97 fps, and your output scan type is interlaced, you can optionally enable hard telecine to create a smoother picture. When you keep the default value, None, MediaConvert does a standard frame rate conversion to 29.97 without doing anything with the field polarity to create a smoother picture.
    pub fn get_telecine(&self) -> &::std::option::Option<crate::types::UncompressedTelecine> {
        &self.telecine
    }
    /// Consumes the builder and constructs a [`UncompressedSettings`](crate::types::UncompressedSettings).
    pub fn build(self) -> crate::types::UncompressedSettings {
        crate::types::UncompressedSettings {
            fourcc: self.fourcc,
            framerate_control: self.framerate_control,
            framerate_conversion_algorithm: self.framerate_conversion_algorithm,
            framerate_denominator: self.framerate_denominator,
            framerate_numerator: self.framerate_numerator,
            interlace_mode: self.interlace_mode,
            scan_type_conversion_mode: self.scan_type_conversion_mode,
            slow_pal: self.slow_pal,
            telecine: self.telecine,
        }
    }
}
