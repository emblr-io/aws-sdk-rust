// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceProfileOutput {
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently recalculated sensitive data discovery statistics and details for the bucket. If the bucket's sensitivity score is calculated automatically, this includes the score.</p>
    pub profile_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive). By default, this score is calculated automatically based on the amount of data that Amazon Macie has analyzed in the bucket and the amount of sensitive data that Macie has found in the bucket.</p>
    pub sensitivity_score: ::std::option::Option<i32>,
    /// <p>Specifies whether the bucket's current sensitivity score was set manually. If this value is true, the score was manually changed to 100. If this value is false, the score was calculated automatically by Amazon Macie.</p>
    pub sensitivity_score_overridden: ::std::option::Option<bool>,
    /// <p>The sensitive data discovery statistics for the bucket. The statistics capture the results of automated sensitive data discovery activities that Amazon Macie has performed for the bucket.</p>
    pub statistics: ::std::option::Option<crate::types::ResourceStatistics>,
    _request_id: Option<String>,
}
impl GetResourceProfileOutput {
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently recalculated sensitive data discovery statistics and details for the bucket. If the bucket's sensitivity score is calculated automatically, this includes the score.</p>
    pub fn profile_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.profile_updated_at.as_ref()
    }
    /// <p>The current sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive). By default, this score is calculated automatically based on the amount of data that Amazon Macie has analyzed in the bucket and the amount of sensitive data that Macie has found in the bucket.</p>
    pub fn sensitivity_score(&self) -> ::std::option::Option<i32> {
        self.sensitivity_score
    }
    /// <p>Specifies whether the bucket's current sensitivity score was set manually. If this value is true, the score was manually changed to 100. If this value is false, the score was calculated automatically by Amazon Macie.</p>
    pub fn sensitivity_score_overridden(&self) -> ::std::option::Option<bool> {
        self.sensitivity_score_overridden
    }
    /// <p>The sensitive data discovery statistics for the bucket. The statistics capture the results of automated sensitive data discovery activities that Amazon Macie has performed for the bucket.</p>
    pub fn statistics(&self) -> ::std::option::Option<&crate::types::ResourceStatistics> {
        self.statistics.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourceProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourceProfileOutput {
    /// Creates a new builder-style object to manufacture [`GetResourceProfileOutput`](crate::operation::get_resource_profile::GetResourceProfileOutput).
    pub fn builder() -> crate::operation::get_resource_profile::builders::GetResourceProfileOutputBuilder {
        crate::operation::get_resource_profile::builders::GetResourceProfileOutputBuilder::default()
    }
}

/// A builder for [`GetResourceProfileOutput`](crate::operation::get_resource_profile::GetResourceProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceProfileOutputBuilder {
    pub(crate) profile_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sensitivity_score: ::std::option::Option<i32>,
    pub(crate) sensitivity_score_overridden: ::std::option::Option<bool>,
    pub(crate) statistics: ::std::option::Option<crate::types::ResourceStatistics>,
    _request_id: Option<String>,
}
impl GetResourceProfileOutputBuilder {
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently recalculated sensitive data discovery statistics and details for the bucket. If the bucket's sensitivity score is calculated automatically, this includes the score.</p>
    pub fn profile_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.profile_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently recalculated sensitive data discovery statistics and details for the bucket. If the bucket's sensitivity score is calculated automatically, this includes the score.</p>
    pub fn set_profile_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.profile_updated_at = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently recalculated sensitive data discovery statistics and details for the bucket. If the bucket's sensitivity score is calculated automatically, this includes the score.</p>
    pub fn get_profile_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.profile_updated_at
    }
    /// <p>The current sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive). By default, this score is calculated automatically based on the amount of data that Amazon Macie has analyzed in the bucket and the amount of sensitive data that Macie has found in the bucket.</p>
    pub fn sensitivity_score(mut self, input: i32) -> Self {
        self.sensitivity_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive). By default, this score is calculated automatically based on the amount of data that Amazon Macie has analyzed in the bucket and the amount of sensitive data that Macie has found in the bucket.</p>
    pub fn set_sensitivity_score(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sensitivity_score = input;
        self
    }
    /// <p>The current sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive). By default, this score is calculated automatically based on the amount of data that Amazon Macie has analyzed in the bucket and the amount of sensitive data that Macie has found in the bucket.</p>
    pub fn get_sensitivity_score(&self) -> &::std::option::Option<i32> {
        &self.sensitivity_score
    }
    /// <p>Specifies whether the bucket's current sensitivity score was set manually. If this value is true, the score was manually changed to 100. If this value is false, the score was calculated automatically by Amazon Macie.</p>
    pub fn sensitivity_score_overridden(mut self, input: bool) -> Self {
        self.sensitivity_score_overridden = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the bucket's current sensitivity score was set manually. If this value is true, the score was manually changed to 100. If this value is false, the score was calculated automatically by Amazon Macie.</p>
    pub fn set_sensitivity_score_overridden(mut self, input: ::std::option::Option<bool>) -> Self {
        self.sensitivity_score_overridden = input;
        self
    }
    /// <p>Specifies whether the bucket's current sensitivity score was set manually. If this value is true, the score was manually changed to 100. If this value is false, the score was calculated automatically by Amazon Macie.</p>
    pub fn get_sensitivity_score_overridden(&self) -> &::std::option::Option<bool> {
        &self.sensitivity_score_overridden
    }
    /// <p>The sensitive data discovery statistics for the bucket. The statistics capture the results of automated sensitive data discovery activities that Amazon Macie has performed for the bucket.</p>
    pub fn statistics(mut self, input: crate::types::ResourceStatistics) -> Self {
        self.statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sensitive data discovery statistics for the bucket. The statistics capture the results of automated sensitive data discovery activities that Amazon Macie has performed for the bucket.</p>
    pub fn set_statistics(mut self, input: ::std::option::Option<crate::types::ResourceStatistics>) -> Self {
        self.statistics = input;
        self
    }
    /// <p>The sensitive data discovery statistics for the bucket. The statistics capture the results of automated sensitive data discovery activities that Amazon Macie has performed for the bucket.</p>
    pub fn get_statistics(&self) -> &::std::option::Option<crate::types::ResourceStatistics> {
        &self.statistics
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetResourceProfileOutput`](crate::operation::get_resource_profile::GetResourceProfileOutput).
    pub fn build(self) -> crate::operation::get_resource_profile::GetResourceProfileOutput {
        crate::operation::get_resource_profile::GetResourceProfileOutput {
            profile_updated_at: self.profile_updated_at,
            sensitivity_score: self.sensitivity_score,
            sensitivity_score_overridden: self.sensitivity_score_overridden,
            statistics: self.statistics,
            _request_id: self._request_id,
        }
    }
}
