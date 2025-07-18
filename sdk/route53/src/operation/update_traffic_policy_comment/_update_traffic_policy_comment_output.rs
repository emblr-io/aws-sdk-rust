// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains the response information for the traffic policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTrafficPolicyCommentOutput {
    /// <p>A complex type that contains settings for the specified traffic policy.</p>
    pub traffic_policy: ::std::option::Option<crate::types::TrafficPolicy>,
    _request_id: Option<String>,
}
impl UpdateTrafficPolicyCommentOutput {
    /// <p>A complex type that contains settings for the specified traffic policy.</p>
    pub fn traffic_policy(&self) -> ::std::option::Option<&crate::types::TrafficPolicy> {
        self.traffic_policy.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateTrafficPolicyCommentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateTrafficPolicyCommentOutput {
    /// Creates a new builder-style object to manufacture [`UpdateTrafficPolicyCommentOutput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentOutput).
    pub fn builder() -> crate::operation::update_traffic_policy_comment::builders::UpdateTrafficPolicyCommentOutputBuilder {
        crate::operation::update_traffic_policy_comment::builders::UpdateTrafficPolicyCommentOutputBuilder::default()
    }
}

/// A builder for [`UpdateTrafficPolicyCommentOutput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTrafficPolicyCommentOutputBuilder {
    pub(crate) traffic_policy: ::std::option::Option<crate::types::TrafficPolicy>,
    _request_id: Option<String>,
}
impl UpdateTrafficPolicyCommentOutputBuilder {
    /// <p>A complex type that contains settings for the specified traffic policy.</p>
    /// This field is required.
    pub fn traffic_policy(mut self, input: crate::types::TrafficPolicy) -> Self {
        self.traffic_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains settings for the specified traffic policy.</p>
    pub fn set_traffic_policy(mut self, input: ::std::option::Option<crate::types::TrafficPolicy>) -> Self {
        self.traffic_policy = input;
        self
    }
    /// <p>A complex type that contains settings for the specified traffic policy.</p>
    pub fn get_traffic_policy(&self) -> &::std::option::Option<crate::types::TrafficPolicy> {
        &self.traffic_policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateTrafficPolicyCommentOutput`](crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentOutput).
    pub fn build(self) -> crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentOutput {
        crate::operation::update_traffic_policy_comment::UpdateTrafficPolicyCommentOutput {
            traffic_policy: self.traffic_policy,
            _request_id: self._request_id,
        }
    }
}
