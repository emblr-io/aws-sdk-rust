// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters for the shot detection segments returned by <code>GetSegmentDetection</code>. For more information, see <code>StartSegmentDetectionFilters</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartShotDetectionFilter {
    /// <p>Specifies the minimum confidence that Amazon Rekognition Video must have in order to return a detected segment. Confidence represents how certain Amazon Rekognition is that a segment is correctly identified. 0 is the lowest confidence. 100 is the highest confidence. Amazon Rekognition Video doesn't return any segments with a confidence level lower than this specified value.</p>
    /// <p>If you don't specify <code>MinSegmentConfidence</code>, the <code>GetSegmentDetection</code> returns segments with confidence values greater than or equal to 50 percent.</p>
    pub min_segment_confidence: ::std::option::Option<f32>,
}
impl StartShotDetectionFilter {
    /// <p>Specifies the minimum confidence that Amazon Rekognition Video must have in order to return a detected segment. Confidence represents how certain Amazon Rekognition is that a segment is correctly identified. 0 is the lowest confidence. 100 is the highest confidence. Amazon Rekognition Video doesn't return any segments with a confidence level lower than this specified value.</p>
    /// <p>If you don't specify <code>MinSegmentConfidence</code>, the <code>GetSegmentDetection</code> returns segments with confidence values greater than or equal to 50 percent.</p>
    pub fn min_segment_confidence(&self) -> ::std::option::Option<f32> {
        self.min_segment_confidence
    }
}
impl StartShotDetectionFilter {
    /// Creates a new builder-style object to manufacture [`StartShotDetectionFilter`](crate::types::StartShotDetectionFilter).
    pub fn builder() -> crate::types::builders::StartShotDetectionFilterBuilder {
        crate::types::builders::StartShotDetectionFilterBuilder::default()
    }
}

/// A builder for [`StartShotDetectionFilter`](crate::types::StartShotDetectionFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartShotDetectionFilterBuilder {
    pub(crate) min_segment_confidence: ::std::option::Option<f32>,
}
impl StartShotDetectionFilterBuilder {
    /// <p>Specifies the minimum confidence that Amazon Rekognition Video must have in order to return a detected segment. Confidence represents how certain Amazon Rekognition is that a segment is correctly identified. 0 is the lowest confidence. 100 is the highest confidence. Amazon Rekognition Video doesn't return any segments with a confidence level lower than this specified value.</p>
    /// <p>If you don't specify <code>MinSegmentConfidence</code>, the <code>GetSegmentDetection</code> returns segments with confidence values greater than or equal to 50 percent.</p>
    pub fn min_segment_confidence(mut self, input: f32) -> Self {
        self.min_segment_confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the minimum confidence that Amazon Rekognition Video must have in order to return a detected segment. Confidence represents how certain Amazon Rekognition is that a segment is correctly identified. 0 is the lowest confidence. 100 is the highest confidence. Amazon Rekognition Video doesn't return any segments with a confidence level lower than this specified value.</p>
    /// <p>If you don't specify <code>MinSegmentConfidence</code>, the <code>GetSegmentDetection</code> returns segments with confidence values greater than or equal to 50 percent.</p>
    pub fn set_min_segment_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.min_segment_confidence = input;
        self
    }
    /// <p>Specifies the minimum confidence that Amazon Rekognition Video must have in order to return a detected segment. Confidence represents how certain Amazon Rekognition is that a segment is correctly identified. 0 is the lowest confidence. 100 is the highest confidence. Amazon Rekognition Video doesn't return any segments with a confidence level lower than this specified value.</p>
    /// <p>If you don't specify <code>MinSegmentConfidence</code>, the <code>GetSegmentDetection</code> returns segments with confidence values greater than or equal to 50 percent.</p>
    pub fn get_min_segment_confidence(&self) -> &::std::option::Option<f32> {
        &self.min_segment_confidence
    }
    /// Consumes the builder and constructs a [`StartShotDetectionFilter`](crate::types::StartShotDetectionFilter).
    pub fn build(self) -> crate::types::StartShotDetectionFilter {
        crate::types::StartShotDetectionFilter {
            min_segment_confidence: self.min_segment_confidence,
        }
    }
}
