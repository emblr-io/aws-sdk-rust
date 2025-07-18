// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchUpdateRecommendationResourceExclusionOutput {
    /// <p>A list of recommendation resource ARNs whose exclusion status failed to update, if any</p>
    pub batch_update_recommendation_resource_exclusion_errors: ::std::vec::Vec<crate::types::UpdateRecommendationResourceExclusionError>,
    _request_id: Option<String>,
}
impl BatchUpdateRecommendationResourceExclusionOutput {
    /// <p>A list of recommendation resource ARNs whose exclusion status failed to update, if any</p>
    pub fn batch_update_recommendation_resource_exclusion_errors(&self) -> &[crate::types::UpdateRecommendationResourceExclusionError] {
        use std::ops::Deref;
        self.batch_update_recommendation_resource_exclusion_errors.deref()
    }
}
impl ::aws_types::request_id::RequestId for BatchUpdateRecommendationResourceExclusionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchUpdateRecommendationResourceExclusionOutput {
    /// Creates a new builder-style object to manufacture [`BatchUpdateRecommendationResourceExclusionOutput`](crate::operation::batch_update_recommendation_resource_exclusion::BatchUpdateRecommendationResourceExclusionOutput).
    pub fn builder(
    ) -> crate::operation::batch_update_recommendation_resource_exclusion::builders::BatchUpdateRecommendationResourceExclusionOutputBuilder {
        crate::operation::batch_update_recommendation_resource_exclusion::builders::BatchUpdateRecommendationResourceExclusionOutputBuilder::default()
    }
}

/// A builder for [`BatchUpdateRecommendationResourceExclusionOutput`](crate::operation::batch_update_recommendation_resource_exclusion::BatchUpdateRecommendationResourceExclusionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchUpdateRecommendationResourceExclusionOutputBuilder {
    pub(crate) batch_update_recommendation_resource_exclusion_errors:
        ::std::option::Option<::std::vec::Vec<crate::types::UpdateRecommendationResourceExclusionError>>,
    _request_id: Option<String>,
}
impl BatchUpdateRecommendationResourceExclusionOutputBuilder {
    /// Appends an item to `batch_update_recommendation_resource_exclusion_errors`.
    ///
    /// To override the contents of this collection use [`set_batch_update_recommendation_resource_exclusion_errors`](Self::set_batch_update_recommendation_resource_exclusion_errors).
    ///
    /// <p>A list of recommendation resource ARNs whose exclusion status failed to update, if any</p>
    pub fn batch_update_recommendation_resource_exclusion_errors(mut self, input: crate::types::UpdateRecommendationResourceExclusionError) -> Self {
        let mut v = self.batch_update_recommendation_resource_exclusion_errors.unwrap_or_default();
        v.push(input);
        self.batch_update_recommendation_resource_exclusion_errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of recommendation resource ARNs whose exclusion status failed to update, if any</p>
    pub fn set_batch_update_recommendation_resource_exclusion_errors(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateRecommendationResourceExclusionError>>,
    ) -> Self {
        self.batch_update_recommendation_resource_exclusion_errors = input;
        self
    }
    /// <p>A list of recommendation resource ARNs whose exclusion status failed to update, if any</p>
    pub fn get_batch_update_recommendation_resource_exclusion_errors(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateRecommendationResourceExclusionError>> {
        &self.batch_update_recommendation_resource_exclusion_errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchUpdateRecommendationResourceExclusionOutput`](crate::operation::batch_update_recommendation_resource_exclusion::BatchUpdateRecommendationResourceExclusionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`batch_update_recommendation_resource_exclusion_errors`](crate::operation::batch_update_recommendation_resource_exclusion::builders::BatchUpdateRecommendationResourceExclusionOutputBuilder::batch_update_recommendation_resource_exclusion_errors)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_update_recommendation_resource_exclusion::BatchUpdateRecommendationResourceExclusionOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::batch_update_recommendation_resource_exclusion::BatchUpdateRecommendationResourceExclusionOutput {
                batch_update_recommendation_resource_exclusion_errors: self.batch_update_recommendation_resource_exclusion_errors
                    .ok_or_else(||
                        ::aws_smithy_types::error::operation::BuildError::missing_field("batch_update_recommendation_resource_exclusion_errors", "batch_update_recommendation_resource_exclusion_errors was not specified but it is required when building BatchUpdateRecommendationResourceExclusionOutput")
                    )?
                ,
                _request_id: self._request_id,
            }
        )
    }
}
