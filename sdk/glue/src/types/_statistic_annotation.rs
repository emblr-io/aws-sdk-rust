// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A Statistic Annotation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StatisticAnnotation {
    /// <p>The Profile ID.</p>
    pub profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The Statistic ID.</p>
    pub statistic_id: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the annotated statistic was recorded.</p>
    pub statistic_recorded_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The inclusion annotation applied to the statistic.</p>
    pub inclusion_annotation: ::std::option::Option<crate::types::TimestampedInclusionAnnotation>,
}
impl StatisticAnnotation {
    /// <p>The Profile ID.</p>
    pub fn profile_id(&self) -> ::std::option::Option<&str> {
        self.profile_id.as_deref()
    }
    /// <p>The Statistic ID.</p>
    pub fn statistic_id(&self) -> ::std::option::Option<&str> {
        self.statistic_id.as_deref()
    }
    /// <p>The timestamp when the annotated statistic was recorded.</p>
    pub fn statistic_recorded_on(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.statistic_recorded_on.as_ref()
    }
    /// <p>The inclusion annotation applied to the statistic.</p>
    pub fn inclusion_annotation(&self) -> ::std::option::Option<&crate::types::TimestampedInclusionAnnotation> {
        self.inclusion_annotation.as_ref()
    }
}
impl StatisticAnnotation {
    /// Creates a new builder-style object to manufacture [`StatisticAnnotation`](crate::types::StatisticAnnotation).
    pub fn builder() -> crate::types::builders::StatisticAnnotationBuilder {
        crate::types::builders::StatisticAnnotationBuilder::default()
    }
}

/// A builder for [`StatisticAnnotation`](crate::types::StatisticAnnotation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StatisticAnnotationBuilder {
    pub(crate) profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) statistic_id: ::std::option::Option<::std::string::String>,
    pub(crate) statistic_recorded_on: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) inclusion_annotation: ::std::option::Option<crate::types::TimestampedInclusionAnnotation>,
}
impl StatisticAnnotationBuilder {
    /// <p>The Profile ID.</p>
    pub fn profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Profile ID.</p>
    pub fn set_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_id = input;
        self
    }
    /// <p>The Profile ID.</p>
    pub fn get_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_id
    }
    /// <p>The Statistic ID.</p>
    pub fn statistic_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statistic_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Statistic ID.</p>
    pub fn set_statistic_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statistic_id = input;
        self
    }
    /// <p>The Statistic ID.</p>
    pub fn get_statistic_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statistic_id
    }
    /// <p>The timestamp when the annotated statistic was recorded.</p>
    pub fn statistic_recorded_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.statistic_recorded_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the annotated statistic was recorded.</p>
    pub fn set_statistic_recorded_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.statistic_recorded_on = input;
        self
    }
    /// <p>The timestamp when the annotated statistic was recorded.</p>
    pub fn get_statistic_recorded_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.statistic_recorded_on
    }
    /// <p>The inclusion annotation applied to the statistic.</p>
    pub fn inclusion_annotation(mut self, input: crate::types::TimestampedInclusionAnnotation) -> Self {
        self.inclusion_annotation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inclusion annotation applied to the statistic.</p>
    pub fn set_inclusion_annotation(mut self, input: ::std::option::Option<crate::types::TimestampedInclusionAnnotation>) -> Self {
        self.inclusion_annotation = input;
        self
    }
    /// <p>The inclusion annotation applied to the statistic.</p>
    pub fn get_inclusion_annotation(&self) -> &::std::option::Option<crate::types::TimestampedInclusionAnnotation> {
        &self.inclusion_annotation
    }
    /// Consumes the builder and constructs a [`StatisticAnnotation`](crate::types::StatisticAnnotation).
    pub fn build(self) -> crate::types::StatisticAnnotation {
        crate::types::StatisticAnnotation {
            profile_id: self.profile_id,
            statistic_id: self.statistic_id,
            statistic_recorded_on: self.statistic_recorded_on,
            inclusion_annotation: self.inclusion_annotation,
        }
    }
}
