// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListReviewPolicyResultsForHitOutput {
    /// <p>The HITId of the HIT for which results have been returned.</p>
    pub hit_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Assignment-level Review Policy. This contains only the PolicyName element.</p>
    pub assignment_review_policy: ::std::option::Option<crate::types::ReviewPolicy>,
    /// <p>The name of the HIT-level Review Policy. This contains only the PolicyName element.</p>
    pub hit_review_policy: ::std::option::Option<crate::types::ReviewPolicy>,
    /// <p>Contains both ReviewResult and ReviewAction elements for an Assignment.</p>
    pub assignment_review_report: ::std::option::Option<crate::types::ReviewReport>,
    /// <p>Contains both ReviewResult and ReviewAction elements for a particular HIT.</p>
    pub hit_review_report: ::std::option::Option<crate::types::ReviewReport>,
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListReviewPolicyResultsForHitOutput {
    /// <p>The HITId of the HIT for which results have been returned.</p>
    pub fn hit_id(&self) -> ::std::option::Option<&str> {
        self.hit_id.as_deref()
    }
    /// <p>The name of the Assignment-level Review Policy. This contains only the PolicyName element.</p>
    pub fn assignment_review_policy(&self) -> ::std::option::Option<&crate::types::ReviewPolicy> {
        self.assignment_review_policy.as_ref()
    }
    /// <p>The name of the HIT-level Review Policy. This contains only the PolicyName element.</p>
    pub fn hit_review_policy(&self) -> ::std::option::Option<&crate::types::ReviewPolicy> {
        self.hit_review_policy.as_ref()
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for an Assignment.</p>
    pub fn assignment_review_report(&self) -> ::std::option::Option<&crate::types::ReviewReport> {
        self.assignment_review_report.as_ref()
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for a particular HIT.</p>
    pub fn hit_review_report(&self) -> ::std::option::Option<&crate::types::ReviewReport> {
        self.hit_review_report.as_ref()
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListReviewPolicyResultsForHitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListReviewPolicyResultsForHitOutput {
    /// Creates a new builder-style object to manufacture [`ListReviewPolicyResultsForHitOutput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitOutput).
    pub fn builder() -> crate::operation::list_review_policy_results_for_hit::builders::ListReviewPolicyResultsForHitOutputBuilder {
        crate::operation::list_review_policy_results_for_hit::builders::ListReviewPolicyResultsForHitOutputBuilder::default()
    }
}

/// A builder for [`ListReviewPolicyResultsForHitOutput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListReviewPolicyResultsForHitOutputBuilder {
    pub(crate) hit_id: ::std::option::Option<::std::string::String>,
    pub(crate) assignment_review_policy: ::std::option::Option<crate::types::ReviewPolicy>,
    pub(crate) hit_review_policy: ::std::option::Option<crate::types::ReviewPolicy>,
    pub(crate) assignment_review_report: ::std::option::Option<crate::types::ReviewReport>,
    pub(crate) hit_review_report: ::std::option::Option<crate::types::ReviewReport>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListReviewPolicyResultsForHitOutputBuilder {
    /// <p>The HITId of the HIT for which results have been returned.</p>
    pub fn hit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HITId of the HIT for which results have been returned.</p>
    pub fn set_hit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hit_id = input;
        self
    }
    /// <p>The HITId of the HIT for which results have been returned.</p>
    pub fn get_hit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hit_id
    }
    /// <p>The name of the Assignment-level Review Policy. This contains only the PolicyName element.</p>
    pub fn assignment_review_policy(mut self, input: crate::types::ReviewPolicy) -> Self {
        self.assignment_review_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the Assignment-level Review Policy. This contains only the PolicyName element.</p>
    pub fn set_assignment_review_policy(mut self, input: ::std::option::Option<crate::types::ReviewPolicy>) -> Self {
        self.assignment_review_policy = input;
        self
    }
    /// <p>The name of the Assignment-level Review Policy. This contains only the PolicyName element.</p>
    pub fn get_assignment_review_policy(&self) -> &::std::option::Option<crate::types::ReviewPolicy> {
        &self.assignment_review_policy
    }
    /// <p>The name of the HIT-level Review Policy. This contains only the PolicyName element.</p>
    pub fn hit_review_policy(mut self, input: crate::types::ReviewPolicy) -> Self {
        self.hit_review_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the HIT-level Review Policy. This contains only the PolicyName element.</p>
    pub fn set_hit_review_policy(mut self, input: ::std::option::Option<crate::types::ReviewPolicy>) -> Self {
        self.hit_review_policy = input;
        self
    }
    /// <p>The name of the HIT-level Review Policy. This contains only the PolicyName element.</p>
    pub fn get_hit_review_policy(&self) -> &::std::option::Option<crate::types::ReviewPolicy> {
        &self.hit_review_policy
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for an Assignment.</p>
    pub fn assignment_review_report(mut self, input: crate::types::ReviewReport) -> Self {
        self.assignment_review_report = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for an Assignment.</p>
    pub fn set_assignment_review_report(mut self, input: ::std::option::Option<crate::types::ReviewReport>) -> Self {
        self.assignment_review_report = input;
        self
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for an Assignment.</p>
    pub fn get_assignment_review_report(&self) -> &::std::option::Option<crate::types::ReviewReport> {
        &self.assignment_review_report
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for a particular HIT.</p>
    pub fn hit_review_report(mut self, input: crate::types::ReviewReport) -> Self {
        self.hit_review_report = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for a particular HIT.</p>
    pub fn set_hit_review_report(mut self, input: ::std::option::Option<crate::types::ReviewReport>) -> Self {
        self.hit_review_report = input;
        self
    }
    /// <p>Contains both ReviewResult and ReviewAction elements for a particular HIT.</p>
    pub fn get_hit_review_report(&self) -> &::std::option::Option<crate::types::ReviewReport> {
        &self.hit_review_report
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListReviewPolicyResultsForHitOutput`](crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitOutput).
    pub fn build(self) -> crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitOutput {
        crate::operation::list_review_policy_results_for_hit::ListReviewPolicyResultsForHitOutput {
            hit_id: self.hit_id,
            assignment_review_policy: self.assignment_review_policy,
            hit_review_policy: self.hit_review_policy,
            assignment_review_report: self.assignment_review_report,
            hit_review_report: self.hit_review_report,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
