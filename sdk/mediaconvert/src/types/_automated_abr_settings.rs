// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Use automated ABR to have MediaConvert set up the renditions in your ABR package for you automatically, based on characteristics of your input video. This feature optimizes video quality while minimizing the overall size of your ABR package.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutomatedAbrSettings {
    /// Specify the maximum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 8,000,000 (8 mb/s) by default. The average bitrate of your highest-quality rendition will be equal to or below this value, depending on the quality, complexity, and resolution of your content. Note that the instantaneous maximum bitrate may vary above the value that you specify.
    pub max_abr_bitrate: ::std::option::Option<i32>,
    /// Optional. Specify the QVBR quality level to use for all renditions in your automated ABR stack. To have MediaConvert automatically determine the quality level: Leave blank. To manually specify a quality level: Enter a value from 1 to 10. MediaConvert will use a quality level up to the value that you specify, depending on your source. For more information about QVBR quality levels, see: https://docs.aws.amazon.com/mediaconvert/latest/ug/qvbr-guidelines.html
    pub max_quality_level: ::std::option::Option<f64>,
    /// Optional. The maximum number of renditions that MediaConvert will create in your automated ABR stack. The number of renditions is determined automatically, based on analysis of each job, but will never exceed this limit. When you set this to Auto in the console, which is equivalent to excluding it from your JSON job specification, MediaConvert defaults to a limit of 15.
    pub max_renditions: ::std::option::Option<i32>,
    /// Specify the minimum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 600,000 (600 kb/s) by default. The average bitrate of your lowest-quality rendition will be near this value. Note that the instantaneous minimum bitrate may vary below the value that you specify.
    pub min_abr_bitrate: ::std::option::Option<i32>,
    /// Optional. Use Automated ABR rules to specify restrictions for the rendition sizes MediaConvert will create in your ABR stack. You can use these rules if your ABR workflow has specific rendition size requirements, but you still want MediaConvert to optimize for video quality and overall file size.
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::AutomatedAbrRule>>,
}
impl AutomatedAbrSettings {
    /// Specify the maximum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 8,000,000 (8 mb/s) by default. The average bitrate of your highest-quality rendition will be equal to or below this value, depending on the quality, complexity, and resolution of your content. Note that the instantaneous maximum bitrate may vary above the value that you specify.
    pub fn max_abr_bitrate(&self) -> ::std::option::Option<i32> {
        self.max_abr_bitrate
    }
    /// Optional. Specify the QVBR quality level to use for all renditions in your automated ABR stack. To have MediaConvert automatically determine the quality level: Leave blank. To manually specify a quality level: Enter a value from 1 to 10. MediaConvert will use a quality level up to the value that you specify, depending on your source. For more information about QVBR quality levels, see: https://docs.aws.amazon.com/mediaconvert/latest/ug/qvbr-guidelines.html
    pub fn max_quality_level(&self) -> ::std::option::Option<f64> {
        self.max_quality_level
    }
    /// Optional. The maximum number of renditions that MediaConvert will create in your automated ABR stack. The number of renditions is determined automatically, based on analysis of each job, but will never exceed this limit. When you set this to Auto in the console, which is equivalent to excluding it from your JSON job specification, MediaConvert defaults to a limit of 15.
    pub fn max_renditions(&self) -> ::std::option::Option<i32> {
        self.max_renditions
    }
    /// Specify the minimum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 600,000 (600 kb/s) by default. The average bitrate of your lowest-quality rendition will be near this value. Note that the instantaneous minimum bitrate may vary below the value that you specify.
    pub fn min_abr_bitrate(&self) -> ::std::option::Option<i32> {
        self.min_abr_bitrate
    }
    /// Optional. Use Automated ABR rules to specify restrictions for the rendition sizes MediaConvert will create in your ABR stack. You can use these rules if your ABR workflow has specific rendition size requirements, but you still want MediaConvert to optimize for video quality and overall file size.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::AutomatedAbrRule] {
        self.rules.as_deref().unwrap_or_default()
    }
}
impl AutomatedAbrSettings {
    /// Creates a new builder-style object to manufacture [`AutomatedAbrSettings`](crate::types::AutomatedAbrSettings).
    pub fn builder() -> crate::types::builders::AutomatedAbrSettingsBuilder {
        crate::types::builders::AutomatedAbrSettingsBuilder::default()
    }
}

/// A builder for [`AutomatedAbrSettings`](crate::types::AutomatedAbrSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutomatedAbrSettingsBuilder {
    pub(crate) max_abr_bitrate: ::std::option::Option<i32>,
    pub(crate) max_quality_level: ::std::option::Option<f64>,
    pub(crate) max_renditions: ::std::option::Option<i32>,
    pub(crate) min_abr_bitrate: ::std::option::Option<i32>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::AutomatedAbrRule>>,
}
impl AutomatedAbrSettingsBuilder {
    /// Specify the maximum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 8,000,000 (8 mb/s) by default. The average bitrate of your highest-quality rendition will be equal to or below this value, depending on the quality, complexity, and resolution of your content. Note that the instantaneous maximum bitrate may vary above the value that you specify.
    pub fn max_abr_bitrate(mut self, input: i32) -> Self {
        self.max_abr_bitrate = ::std::option::Option::Some(input);
        self
    }
    /// Specify the maximum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 8,000,000 (8 mb/s) by default. The average bitrate of your highest-quality rendition will be equal to or below this value, depending on the quality, complexity, and resolution of your content. Note that the instantaneous maximum bitrate may vary above the value that you specify.
    pub fn set_max_abr_bitrate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_abr_bitrate = input;
        self
    }
    /// Specify the maximum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 8,000,000 (8 mb/s) by default. The average bitrate of your highest-quality rendition will be equal to or below this value, depending on the quality, complexity, and resolution of your content. Note that the instantaneous maximum bitrate may vary above the value that you specify.
    pub fn get_max_abr_bitrate(&self) -> &::std::option::Option<i32> {
        &self.max_abr_bitrate
    }
    /// Optional. Specify the QVBR quality level to use for all renditions in your automated ABR stack. To have MediaConvert automatically determine the quality level: Leave blank. To manually specify a quality level: Enter a value from 1 to 10. MediaConvert will use a quality level up to the value that you specify, depending on your source. For more information about QVBR quality levels, see: https://docs.aws.amazon.com/mediaconvert/latest/ug/qvbr-guidelines.html
    pub fn max_quality_level(mut self, input: f64) -> Self {
        self.max_quality_level = ::std::option::Option::Some(input);
        self
    }
    /// Optional. Specify the QVBR quality level to use for all renditions in your automated ABR stack. To have MediaConvert automatically determine the quality level: Leave blank. To manually specify a quality level: Enter a value from 1 to 10. MediaConvert will use a quality level up to the value that you specify, depending on your source. For more information about QVBR quality levels, see: https://docs.aws.amazon.com/mediaconvert/latest/ug/qvbr-guidelines.html
    pub fn set_max_quality_level(mut self, input: ::std::option::Option<f64>) -> Self {
        self.max_quality_level = input;
        self
    }
    /// Optional. Specify the QVBR quality level to use for all renditions in your automated ABR stack. To have MediaConvert automatically determine the quality level: Leave blank. To manually specify a quality level: Enter a value from 1 to 10. MediaConvert will use a quality level up to the value that you specify, depending on your source. For more information about QVBR quality levels, see: https://docs.aws.amazon.com/mediaconvert/latest/ug/qvbr-guidelines.html
    pub fn get_max_quality_level(&self) -> &::std::option::Option<f64> {
        &self.max_quality_level
    }
    /// Optional. The maximum number of renditions that MediaConvert will create in your automated ABR stack. The number of renditions is determined automatically, based on analysis of each job, but will never exceed this limit. When you set this to Auto in the console, which is equivalent to excluding it from your JSON job specification, MediaConvert defaults to a limit of 15.
    pub fn max_renditions(mut self, input: i32) -> Self {
        self.max_renditions = ::std::option::Option::Some(input);
        self
    }
    /// Optional. The maximum number of renditions that MediaConvert will create in your automated ABR stack. The number of renditions is determined automatically, based on analysis of each job, but will never exceed this limit. When you set this to Auto in the console, which is equivalent to excluding it from your JSON job specification, MediaConvert defaults to a limit of 15.
    pub fn set_max_renditions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_renditions = input;
        self
    }
    /// Optional. The maximum number of renditions that MediaConvert will create in your automated ABR stack. The number of renditions is determined automatically, based on analysis of each job, but will never exceed this limit. When you set this to Auto in the console, which is equivalent to excluding it from your JSON job specification, MediaConvert defaults to a limit of 15.
    pub fn get_max_renditions(&self) -> &::std::option::Option<i32> {
        &self.max_renditions
    }
    /// Specify the minimum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 600,000 (600 kb/s) by default. The average bitrate of your lowest-quality rendition will be near this value. Note that the instantaneous minimum bitrate may vary below the value that you specify.
    pub fn min_abr_bitrate(mut self, input: i32) -> Self {
        self.min_abr_bitrate = ::std::option::Option::Some(input);
        self
    }
    /// Specify the minimum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 600,000 (600 kb/s) by default. The average bitrate of your lowest-quality rendition will be near this value. Note that the instantaneous minimum bitrate may vary below the value that you specify.
    pub fn set_min_abr_bitrate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_abr_bitrate = input;
        self
    }
    /// Specify the minimum average bitrate for MediaConvert to use in your automated ABR stack. If you don't specify a value, MediaConvert uses 600,000 (600 kb/s) by default. The average bitrate of your lowest-quality rendition will be near this value. Note that the instantaneous minimum bitrate may vary below the value that you specify.
    pub fn get_min_abr_bitrate(&self) -> &::std::option::Option<i32> {
        &self.min_abr_bitrate
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// Optional. Use Automated ABR rules to specify restrictions for the rendition sizes MediaConvert will create in your ABR stack. You can use these rules if your ABR workflow has specific rendition size requirements, but you still want MediaConvert to optimize for video quality and overall file size.
    pub fn rules(mut self, input: crate::types::AutomatedAbrRule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// Optional. Use Automated ABR rules to specify restrictions for the rendition sizes MediaConvert will create in your ABR stack. You can use these rules if your ABR workflow has specific rendition size requirements, but you still want MediaConvert to optimize for video quality and overall file size.
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AutomatedAbrRule>>) -> Self {
        self.rules = input;
        self
    }
    /// Optional. Use Automated ABR rules to specify restrictions for the rendition sizes MediaConvert will create in your ABR stack. You can use these rules if your ABR workflow has specific rendition size requirements, but you still want MediaConvert to optimize for video quality and overall file size.
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutomatedAbrRule>> {
        &self.rules
    }
    /// Consumes the builder and constructs a [`AutomatedAbrSettings`](crate::types::AutomatedAbrSettings).
    pub fn build(self) -> crate::types::AutomatedAbrSettings {
        crate::types::AutomatedAbrSettings {
            max_abr_bitrate: self.max_abr_bitrate,
            max_quality_level: self.max_quality_level,
            max_renditions: self.max_renditions,
            min_abr_bitrate: self.min_abr_bitrate,
            rules: self.rules,
        }
    }
}
