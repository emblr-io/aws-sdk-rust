// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a technical cue segment. For more information, see <code>SegmentDetection</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TechnicalCueSegment {
    /// <p>The type of the technical cue.</p>
    pub r#type: ::std::option::Option<crate::types::TechnicalCueType>,
    /// <p>The confidence that Amazon Rekognition Video has in the accuracy of the detected segment.</p>
    pub confidence: ::std::option::Option<f32>,
}
impl TechnicalCueSegment {
    /// <p>The type of the technical cue.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TechnicalCueType> {
        self.r#type.as_ref()
    }
    /// <p>The confidence that Amazon Rekognition Video has in the accuracy of the detected segment.</p>
    pub fn confidence(&self) -> ::std::option::Option<f32> {
        self.confidence
    }
}
impl TechnicalCueSegment {
    /// Creates a new builder-style object to manufacture [`TechnicalCueSegment`](crate::types::TechnicalCueSegment).
    pub fn builder() -> crate::types::builders::TechnicalCueSegmentBuilder {
        crate::types::builders::TechnicalCueSegmentBuilder::default()
    }
}

/// A builder for [`TechnicalCueSegment`](crate::types::TechnicalCueSegment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TechnicalCueSegmentBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::TechnicalCueType>,
    pub(crate) confidence: ::std::option::Option<f32>,
}
impl TechnicalCueSegmentBuilder {
    /// <p>The type of the technical cue.</p>
    pub fn r#type(mut self, input: crate::types::TechnicalCueType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the technical cue.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TechnicalCueType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the technical cue.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TechnicalCueType> {
        &self.r#type
    }
    /// <p>The confidence that Amazon Rekognition Video has in the accuracy of the detected segment.</p>
    pub fn confidence(mut self, input: f32) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>The confidence that Amazon Rekognition Video has in the accuracy of the detected segment.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>The confidence that Amazon Rekognition Video has in the accuracy of the detected segment.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<f32> {
        &self.confidence
    }
    /// Consumes the builder and constructs a [`TechnicalCueSegment`](crate::types::TechnicalCueSegment).
    pub fn build(self) -> crate::types::TechnicalCueSegment {
        crate::types::TechnicalCueSegment {
            r#type: self.r#type,
            confidence: self.confidence,
        }
    }
}
