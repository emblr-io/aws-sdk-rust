// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSamplingTargetsOutput {
    /// <p>Updated rules that the service should use to sample requests.</p>
    pub sampling_target_documents: ::std::option::Option<::std::vec::Vec<crate::types::SamplingTargetDocument>>,
    /// <p>The last time a user changed the sampling rule configuration. If the sampling rule configuration changed since the service last retrieved it, the service should call <a href="https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingRules.html">GetSamplingRules</a> to get the latest version.</p>
    pub last_rule_modification: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Information about <a href="https://docs.aws.amazon.com/xray/latest/api/API_SamplingStatisticsDocument.html">SamplingStatisticsDocument</a> that X-Ray could not process.</p>
    pub unprocessed_statistics: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedStatistics>>,
    _request_id: Option<String>,
}
impl GetSamplingTargetsOutput {
    /// <p>Updated rules that the service should use to sample requests.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sampling_target_documents.is_none()`.
    pub fn sampling_target_documents(&self) -> &[crate::types::SamplingTargetDocument] {
        self.sampling_target_documents.as_deref().unwrap_or_default()
    }
    /// <p>The last time a user changed the sampling rule configuration. If the sampling rule configuration changed since the service last retrieved it, the service should call <a href="https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingRules.html">GetSamplingRules</a> to get the latest version.</p>
    pub fn last_rule_modification(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_rule_modification.as_ref()
    }
    /// <p>Information about <a href="https://docs.aws.amazon.com/xray/latest/api/API_SamplingStatisticsDocument.html">SamplingStatisticsDocument</a> that X-Ray could not process.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unprocessed_statistics.is_none()`.
    pub fn unprocessed_statistics(&self) -> &[crate::types::UnprocessedStatistics] {
        self.unprocessed_statistics.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetSamplingTargetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSamplingTargetsOutput {
    /// Creates a new builder-style object to manufacture [`GetSamplingTargetsOutput`](crate::operation::get_sampling_targets::GetSamplingTargetsOutput).
    pub fn builder() -> crate::operation::get_sampling_targets::builders::GetSamplingTargetsOutputBuilder {
        crate::operation::get_sampling_targets::builders::GetSamplingTargetsOutputBuilder::default()
    }
}

/// A builder for [`GetSamplingTargetsOutput`](crate::operation::get_sampling_targets::GetSamplingTargetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSamplingTargetsOutputBuilder {
    pub(crate) sampling_target_documents: ::std::option::Option<::std::vec::Vec<crate::types::SamplingTargetDocument>>,
    pub(crate) last_rule_modification: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) unprocessed_statistics: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedStatistics>>,
    _request_id: Option<String>,
}
impl GetSamplingTargetsOutputBuilder {
    /// Appends an item to `sampling_target_documents`.
    ///
    /// To override the contents of this collection use [`set_sampling_target_documents`](Self::set_sampling_target_documents).
    ///
    /// <p>Updated rules that the service should use to sample requests.</p>
    pub fn sampling_target_documents(mut self, input: crate::types::SamplingTargetDocument) -> Self {
        let mut v = self.sampling_target_documents.unwrap_or_default();
        v.push(input);
        self.sampling_target_documents = ::std::option::Option::Some(v);
        self
    }
    /// <p>Updated rules that the service should use to sample requests.</p>
    pub fn set_sampling_target_documents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SamplingTargetDocument>>) -> Self {
        self.sampling_target_documents = input;
        self
    }
    /// <p>Updated rules that the service should use to sample requests.</p>
    pub fn get_sampling_target_documents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SamplingTargetDocument>> {
        &self.sampling_target_documents
    }
    /// <p>The last time a user changed the sampling rule configuration. If the sampling rule configuration changed since the service last retrieved it, the service should call <a href="https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingRules.html">GetSamplingRules</a> to get the latest version.</p>
    pub fn last_rule_modification(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_rule_modification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time a user changed the sampling rule configuration. If the sampling rule configuration changed since the service last retrieved it, the service should call <a href="https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingRules.html">GetSamplingRules</a> to get the latest version.</p>
    pub fn set_last_rule_modification(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_rule_modification = input;
        self
    }
    /// <p>The last time a user changed the sampling rule configuration. If the sampling rule configuration changed since the service last retrieved it, the service should call <a href="https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingRules.html">GetSamplingRules</a> to get the latest version.</p>
    pub fn get_last_rule_modification(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_rule_modification
    }
    /// Appends an item to `unprocessed_statistics`.
    ///
    /// To override the contents of this collection use [`set_unprocessed_statistics`](Self::set_unprocessed_statistics).
    ///
    /// <p>Information about <a href="https://docs.aws.amazon.com/xray/latest/api/API_SamplingStatisticsDocument.html">SamplingStatisticsDocument</a> that X-Ray could not process.</p>
    pub fn unprocessed_statistics(mut self, input: crate::types::UnprocessedStatistics) -> Self {
        let mut v = self.unprocessed_statistics.unwrap_or_default();
        v.push(input);
        self.unprocessed_statistics = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about <a href="https://docs.aws.amazon.com/xray/latest/api/API_SamplingStatisticsDocument.html">SamplingStatisticsDocument</a> that X-Ray could not process.</p>
    pub fn set_unprocessed_statistics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnprocessedStatistics>>) -> Self {
        self.unprocessed_statistics = input;
        self
    }
    /// <p>Information about <a href="https://docs.aws.amazon.com/xray/latest/api/API_SamplingStatisticsDocument.html">SamplingStatisticsDocument</a> that X-Ray could not process.</p>
    pub fn get_unprocessed_statistics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnprocessedStatistics>> {
        &self.unprocessed_statistics
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSamplingTargetsOutput`](crate::operation::get_sampling_targets::GetSamplingTargetsOutput).
    pub fn build(self) -> crate::operation::get_sampling_targets::GetSamplingTargetsOutput {
        crate::operation::get_sampling_targets::GetSamplingTargetsOutput {
            sampling_target_documents: self.sampling_target_documents,
            last_rule_modification: self.last_rule_modification,
            unprocessed_statistics: self.unprocessed_statistics,
            _request_id: self._request_id,
        }
    }
}
