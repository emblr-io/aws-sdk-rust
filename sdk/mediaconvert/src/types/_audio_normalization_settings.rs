// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Advanced audio normalization settings. Ignore these settings unless you need to comply with a loudness standard.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioNormalizationSettings {
    /// Choose one of the following audio normalization algorithms: ITU-R BS.1770-1: Ungated loudness. A measurement of ungated average loudness for an entire piece of content, suitable for measurement of short-form content under ATSC recommendation A/85. Supports up to 5.1 audio channels. ITU-R BS.1770-2: Gated loudness. A measurement of gated average loudness compliant with the requirements of EBU-R128. Supports up to 5.1 audio channels. ITU-R BS.1770-3: Modified peak. The same loudness measurement algorithm as 1770-2, with an updated true peak measurement. ITU-R BS.1770-4: Higher channel count. Allows for more audio channels than the other algorithms, including configurations such as 7.1.
    pub algorithm: ::std::option::Option<crate::types::AudioNormalizationAlgorithm>,
    /// When enabled the output audio is corrected using the chosen algorithm. If disabled, the audio will be measured but not adjusted.
    pub algorithm_control: ::std::option::Option<crate::types::AudioNormalizationAlgorithmControl>,
    /// Content measuring above this level will be corrected to the target level. Content measuring below this level will not be corrected.
    pub correction_gate_level: ::std::option::Option<i32>,
    /// If set to LOG, log each output's audio track loudness to a CSV file.
    pub loudness_logging: ::std::option::Option<crate::types::AudioNormalizationLoudnessLogging>,
    /// If set to TRUE_PEAK, calculate and log the TruePeak for each output's audio track loudness.
    pub peak_calculation: ::std::option::Option<crate::types::AudioNormalizationPeakCalculation>,
    /// When you use Audio normalization, optionally use this setting to specify a target loudness. If you don't specify a value here, the encoder chooses a value for you, based on the algorithm that you choose for Algorithm. If you choose algorithm 1770-1, the encoder will choose -24 LKFS; otherwise, the encoder will choose -23 LKFS.
    pub target_lkfs: ::std::option::Option<f64>,
    /// Specify the True-peak limiter threshold in decibels relative to full scale (dBFS). The peak inter-audio sample loudness in your output will be limited to the value that you specify, without affecting the overall target LKFS. Enter a value from 0 to -8. Leave blank to use the default value 0.
    pub true_peak_limiter_threshold: ::std::option::Option<f64>,
}
impl AudioNormalizationSettings {
    /// Choose one of the following audio normalization algorithms: ITU-R BS.1770-1: Ungated loudness. A measurement of ungated average loudness for an entire piece of content, suitable for measurement of short-form content under ATSC recommendation A/85. Supports up to 5.1 audio channels. ITU-R BS.1770-2: Gated loudness. A measurement of gated average loudness compliant with the requirements of EBU-R128. Supports up to 5.1 audio channels. ITU-R BS.1770-3: Modified peak. The same loudness measurement algorithm as 1770-2, with an updated true peak measurement. ITU-R BS.1770-4: Higher channel count. Allows for more audio channels than the other algorithms, including configurations such as 7.1.
    pub fn algorithm(&self) -> ::std::option::Option<&crate::types::AudioNormalizationAlgorithm> {
        self.algorithm.as_ref()
    }
    /// When enabled the output audio is corrected using the chosen algorithm. If disabled, the audio will be measured but not adjusted.
    pub fn algorithm_control(&self) -> ::std::option::Option<&crate::types::AudioNormalizationAlgorithmControl> {
        self.algorithm_control.as_ref()
    }
    /// Content measuring above this level will be corrected to the target level. Content measuring below this level will not be corrected.
    pub fn correction_gate_level(&self) -> ::std::option::Option<i32> {
        self.correction_gate_level
    }
    /// If set to LOG, log each output's audio track loudness to a CSV file.
    pub fn loudness_logging(&self) -> ::std::option::Option<&crate::types::AudioNormalizationLoudnessLogging> {
        self.loudness_logging.as_ref()
    }
    /// If set to TRUE_PEAK, calculate and log the TruePeak for each output's audio track loudness.
    pub fn peak_calculation(&self) -> ::std::option::Option<&crate::types::AudioNormalizationPeakCalculation> {
        self.peak_calculation.as_ref()
    }
    /// When you use Audio normalization, optionally use this setting to specify a target loudness. If you don't specify a value here, the encoder chooses a value for you, based on the algorithm that you choose for Algorithm. If you choose algorithm 1770-1, the encoder will choose -24 LKFS; otherwise, the encoder will choose -23 LKFS.
    pub fn target_lkfs(&self) -> ::std::option::Option<f64> {
        self.target_lkfs
    }
    /// Specify the True-peak limiter threshold in decibels relative to full scale (dBFS). The peak inter-audio sample loudness in your output will be limited to the value that you specify, without affecting the overall target LKFS. Enter a value from 0 to -8. Leave blank to use the default value 0.
    pub fn true_peak_limiter_threshold(&self) -> ::std::option::Option<f64> {
        self.true_peak_limiter_threshold
    }
}
impl AudioNormalizationSettings {
    /// Creates a new builder-style object to manufacture [`AudioNormalizationSettings`](crate::types::AudioNormalizationSettings).
    pub fn builder() -> crate::types::builders::AudioNormalizationSettingsBuilder {
        crate::types::builders::AudioNormalizationSettingsBuilder::default()
    }
}

/// A builder for [`AudioNormalizationSettings`](crate::types::AudioNormalizationSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioNormalizationSettingsBuilder {
    pub(crate) algorithm: ::std::option::Option<crate::types::AudioNormalizationAlgorithm>,
    pub(crate) algorithm_control: ::std::option::Option<crate::types::AudioNormalizationAlgorithmControl>,
    pub(crate) correction_gate_level: ::std::option::Option<i32>,
    pub(crate) loudness_logging: ::std::option::Option<crate::types::AudioNormalizationLoudnessLogging>,
    pub(crate) peak_calculation: ::std::option::Option<crate::types::AudioNormalizationPeakCalculation>,
    pub(crate) target_lkfs: ::std::option::Option<f64>,
    pub(crate) true_peak_limiter_threshold: ::std::option::Option<f64>,
}
impl AudioNormalizationSettingsBuilder {
    /// Choose one of the following audio normalization algorithms: ITU-R BS.1770-1: Ungated loudness. A measurement of ungated average loudness for an entire piece of content, suitable for measurement of short-form content under ATSC recommendation A/85. Supports up to 5.1 audio channels. ITU-R BS.1770-2: Gated loudness. A measurement of gated average loudness compliant with the requirements of EBU-R128. Supports up to 5.1 audio channels. ITU-R BS.1770-3: Modified peak. The same loudness measurement algorithm as 1770-2, with an updated true peak measurement. ITU-R BS.1770-4: Higher channel count. Allows for more audio channels than the other algorithms, including configurations such as 7.1.
    pub fn algorithm(mut self, input: crate::types::AudioNormalizationAlgorithm) -> Self {
        self.algorithm = ::std::option::Option::Some(input);
        self
    }
    /// Choose one of the following audio normalization algorithms: ITU-R BS.1770-1: Ungated loudness. A measurement of ungated average loudness for an entire piece of content, suitable for measurement of short-form content under ATSC recommendation A/85. Supports up to 5.1 audio channels. ITU-R BS.1770-2: Gated loudness. A measurement of gated average loudness compliant with the requirements of EBU-R128. Supports up to 5.1 audio channels. ITU-R BS.1770-3: Modified peak. The same loudness measurement algorithm as 1770-2, with an updated true peak measurement. ITU-R BS.1770-4: Higher channel count. Allows for more audio channels than the other algorithms, including configurations such as 7.1.
    pub fn set_algorithm(mut self, input: ::std::option::Option<crate::types::AudioNormalizationAlgorithm>) -> Self {
        self.algorithm = input;
        self
    }
    /// Choose one of the following audio normalization algorithms: ITU-R BS.1770-1: Ungated loudness. A measurement of ungated average loudness for an entire piece of content, suitable for measurement of short-form content under ATSC recommendation A/85. Supports up to 5.1 audio channels. ITU-R BS.1770-2: Gated loudness. A measurement of gated average loudness compliant with the requirements of EBU-R128. Supports up to 5.1 audio channels. ITU-R BS.1770-3: Modified peak. The same loudness measurement algorithm as 1770-2, with an updated true peak measurement. ITU-R BS.1770-4: Higher channel count. Allows for more audio channels than the other algorithms, including configurations such as 7.1.
    pub fn get_algorithm(&self) -> &::std::option::Option<crate::types::AudioNormalizationAlgorithm> {
        &self.algorithm
    }
    /// When enabled the output audio is corrected using the chosen algorithm. If disabled, the audio will be measured but not adjusted.
    pub fn algorithm_control(mut self, input: crate::types::AudioNormalizationAlgorithmControl) -> Self {
        self.algorithm_control = ::std::option::Option::Some(input);
        self
    }
    /// When enabled the output audio is corrected using the chosen algorithm. If disabled, the audio will be measured but not adjusted.
    pub fn set_algorithm_control(mut self, input: ::std::option::Option<crate::types::AudioNormalizationAlgorithmControl>) -> Self {
        self.algorithm_control = input;
        self
    }
    /// When enabled the output audio is corrected using the chosen algorithm. If disabled, the audio will be measured but not adjusted.
    pub fn get_algorithm_control(&self) -> &::std::option::Option<crate::types::AudioNormalizationAlgorithmControl> {
        &self.algorithm_control
    }
    /// Content measuring above this level will be corrected to the target level. Content measuring below this level will not be corrected.
    pub fn correction_gate_level(mut self, input: i32) -> Self {
        self.correction_gate_level = ::std::option::Option::Some(input);
        self
    }
    /// Content measuring above this level will be corrected to the target level. Content measuring below this level will not be corrected.
    pub fn set_correction_gate_level(mut self, input: ::std::option::Option<i32>) -> Self {
        self.correction_gate_level = input;
        self
    }
    /// Content measuring above this level will be corrected to the target level. Content measuring below this level will not be corrected.
    pub fn get_correction_gate_level(&self) -> &::std::option::Option<i32> {
        &self.correction_gate_level
    }
    /// If set to LOG, log each output's audio track loudness to a CSV file.
    pub fn loudness_logging(mut self, input: crate::types::AudioNormalizationLoudnessLogging) -> Self {
        self.loudness_logging = ::std::option::Option::Some(input);
        self
    }
    /// If set to LOG, log each output's audio track loudness to a CSV file.
    pub fn set_loudness_logging(mut self, input: ::std::option::Option<crate::types::AudioNormalizationLoudnessLogging>) -> Self {
        self.loudness_logging = input;
        self
    }
    /// If set to LOG, log each output's audio track loudness to a CSV file.
    pub fn get_loudness_logging(&self) -> &::std::option::Option<crate::types::AudioNormalizationLoudnessLogging> {
        &self.loudness_logging
    }
    /// If set to TRUE_PEAK, calculate and log the TruePeak for each output's audio track loudness.
    pub fn peak_calculation(mut self, input: crate::types::AudioNormalizationPeakCalculation) -> Self {
        self.peak_calculation = ::std::option::Option::Some(input);
        self
    }
    /// If set to TRUE_PEAK, calculate and log the TruePeak for each output's audio track loudness.
    pub fn set_peak_calculation(mut self, input: ::std::option::Option<crate::types::AudioNormalizationPeakCalculation>) -> Self {
        self.peak_calculation = input;
        self
    }
    /// If set to TRUE_PEAK, calculate and log the TruePeak for each output's audio track loudness.
    pub fn get_peak_calculation(&self) -> &::std::option::Option<crate::types::AudioNormalizationPeakCalculation> {
        &self.peak_calculation
    }
    /// When you use Audio normalization, optionally use this setting to specify a target loudness. If you don't specify a value here, the encoder chooses a value for you, based on the algorithm that you choose for Algorithm. If you choose algorithm 1770-1, the encoder will choose -24 LKFS; otherwise, the encoder will choose -23 LKFS.
    pub fn target_lkfs(mut self, input: f64) -> Self {
        self.target_lkfs = ::std::option::Option::Some(input);
        self
    }
    /// When you use Audio normalization, optionally use this setting to specify a target loudness. If you don't specify a value here, the encoder chooses a value for you, based on the algorithm that you choose for Algorithm. If you choose algorithm 1770-1, the encoder will choose -24 LKFS; otherwise, the encoder will choose -23 LKFS.
    pub fn set_target_lkfs(mut self, input: ::std::option::Option<f64>) -> Self {
        self.target_lkfs = input;
        self
    }
    /// When you use Audio normalization, optionally use this setting to specify a target loudness. If you don't specify a value here, the encoder chooses a value for you, based on the algorithm that you choose for Algorithm. If you choose algorithm 1770-1, the encoder will choose -24 LKFS; otherwise, the encoder will choose -23 LKFS.
    pub fn get_target_lkfs(&self) -> &::std::option::Option<f64> {
        &self.target_lkfs
    }
    /// Specify the True-peak limiter threshold in decibels relative to full scale (dBFS). The peak inter-audio sample loudness in your output will be limited to the value that you specify, without affecting the overall target LKFS. Enter a value from 0 to -8. Leave blank to use the default value 0.
    pub fn true_peak_limiter_threshold(mut self, input: f64) -> Self {
        self.true_peak_limiter_threshold = ::std::option::Option::Some(input);
        self
    }
    /// Specify the True-peak limiter threshold in decibels relative to full scale (dBFS). The peak inter-audio sample loudness in your output will be limited to the value that you specify, without affecting the overall target LKFS. Enter a value from 0 to -8. Leave blank to use the default value 0.
    pub fn set_true_peak_limiter_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.true_peak_limiter_threshold = input;
        self
    }
    /// Specify the True-peak limiter threshold in decibels relative to full scale (dBFS). The peak inter-audio sample loudness in your output will be limited to the value that you specify, without affecting the overall target LKFS. Enter a value from 0 to -8. Leave blank to use the default value 0.
    pub fn get_true_peak_limiter_threshold(&self) -> &::std::option::Option<f64> {
        &self.true_peak_limiter_threshold
    }
    /// Consumes the builder and constructs a [`AudioNormalizationSettings`](crate::types::AudioNormalizationSettings).
    pub fn build(self) -> crate::types::AudioNormalizationSettings {
        crate::types::AudioNormalizationSettings {
            algorithm: self.algorithm,
            algorithm_control: self.algorithm_control,
            correction_gate_level: self.correction_gate_level,
            loudness_logging: self.loudness_logging,
            peak_calculation: self.peak_calculation,
            target_lkfs: self.target_lkfs,
            true_peak_limiter_threshold: self.true_peak_limiter_threshold,
        }
    }
}
