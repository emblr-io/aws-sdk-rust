// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchPutDataQualityStatisticAnnotationOutput {
    /// <p>A list of <code>AnnotationError</code>'s.</p>
    pub failed_inclusion_annotations: ::std::option::Option<::std::vec::Vec<crate::types::AnnotationError>>,
    _request_id: Option<String>,
}
impl BatchPutDataQualityStatisticAnnotationOutput {
    /// <p>A list of <code>AnnotationError</code>'s.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failed_inclusion_annotations.is_none()`.
    pub fn failed_inclusion_annotations(&self) -> &[crate::types::AnnotationError] {
        self.failed_inclusion_annotations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchPutDataQualityStatisticAnnotationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchPutDataQualityStatisticAnnotationOutput {
    /// Creates a new builder-style object to manufacture [`BatchPutDataQualityStatisticAnnotationOutput`](crate::operation::batch_put_data_quality_statistic_annotation::BatchPutDataQualityStatisticAnnotationOutput).
    pub fn builder() -> crate::operation::batch_put_data_quality_statistic_annotation::builders::BatchPutDataQualityStatisticAnnotationOutputBuilder {
        crate::operation::batch_put_data_quality_statistic_annotation::builders::BatchPutDataQualityStatisticAnnotationOutputBuilder::default()
    }
}

/// A builder for [`BatchPutDataQualityStatisticAnnotationOutput`](crate::operation::batch_put_data_quality_statistic_annotation::BatchPutDataQualityStatisticAnnotationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchPutDataQualityStatisticAnnotationOutputBuilder {
    pub(crate) failed_inclusion_annotations: ::std::option::Option<::std::vec::Vec<crate::types::AnnotationError>>,
    _request_id: Option<String>,
}
impl BatchPutDataQualityStatisticAnnotationOutputBuilder {
    /// Appends an item to `failed_inclusion_annotations`.
    ///
    /// To override the contents of this collection use [`set_failed_inclusion_annotations`](Self::set_failed_inclusion_annotations).
    ///
    /// <p>A list of <code>AnnotationError</code>'s.</p>
    pub fn failed_inclusion_annotations(mut self, input: crate::types::AnnotationError) -> Self {
        let mut v = self.failed_inclusion_annotations.unwrap_or_default();
        v.push(input);
        self.failed_inclusion_annotations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>AnnotationError</code>'s.</p>
    pub fn set_failed_inclusion_annotations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AnnotationError>>) -> Self {
        self.failed_inclusion_annotations = input;
        self
    }
    /// <p>A list of <code>AnnotationError</code>'s.</p>
    pub fn get_failed_inclusion_annotations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AnnotationError>> {
        &self.failed_inclusion_annotations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchPutDataQualityStatisticAnnotationOutput`](crate::operation::batch_put_data_quality_statistic_annotation::BatchPutDataQualityStatisticAnnotationOutput).
    pub fn build(self) -> crate::operation::batch_put_data_quality_statistic_annotation::BatchPutDataQualityStatisticAnnotationOutput {
        crate::operation::batch_put_data_quality_statistic_annotation::BatchPutDataQualityStatisticAnnotationOutput {
            failed_inclusion_annotations: self.failed_inclusion_annotations,
            _request_id: self._request_id,
        }
    }
}
