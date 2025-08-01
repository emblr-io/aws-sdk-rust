// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetEffectiveLifecyclePolicyOutput {
    /// <p>A list of lifecycle policies applied to the OpenSearch Serverless indexes.</p>
    pub effective_lifecycle_policy_details: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyDetail>>,
    /// <p>A list of resources for which retrieval failed.</p>
    pub effective_lifecycle_policy_error_details: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyErrorDetail>>,
    _request_id: Option<String>,
}
impl BatchGetEffectiveLifecyclePolicyOutput {
    /// <p>A list of lifecycle policies applied to the OpenSearch Serverless indexes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.effective_lifecycle_policy_details.is_none()`.
    pub fn effective_lifecycle_policy_details(&self) -> &[crate::types::EffectiveLifecyclePolicyDetail] {
        self.effective_lifecycle_policy_details.as_deref().unwrap_or_default()
    }
    /// <p>A list of resources for which retrieval failed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.effective_lifecycle_policy_error_details.is_none()`.
    pub fn effective_lifecycle_policy_error_details(&self) -> &[crate::types::EffectiveLifecyclePolicyErrorDetail] {
        self.effective_lifecycle_policy_error_details.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetEffectiveLifecyclePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetEffectiveLifecyclePolicyOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetEffectiveLifecyclePolicyOutput`](crate::operation::batch_get_effective_lifecycle_policy::BatchGetEffectiveLifecyclePolicyOutput).
    pub fn builder() -> crate::operation::batch_get_effective_lifecycle_policy::builders::BatchGetEffectiveLifecyclePolicyOutputBuilder {
        crate::operation::batch_get_effective_lifecycle_policy::builders::BatchGetEffectiveLifecyclePolicyOutputBuilder::default()
    }
}

/// A builder for [`BatchGetEffectiveLifecyclePolicyOutput`](crate::operation::batch_get_effective_lifecycle_policy::BatchGetEffectiveLifecyclePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetEffectiveLifecyclePolicyOutputBuilder {
    pub(crate) effective_lifecycle_policy_details: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyDetail>>,
    pub(crate) effective_lifecycle_policy_error_details: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyErrorDetail>>,
    _request_id: Option<String>,
}
impl BatchGetEffectiveLifecyclePolicyOutputBuilder {
    /// Appends an item to `effective_lifecycle_policy_details`.
    ///
    /// To override the contents of this collection use [`set_effective_lifecycle_policy_details`](Self::set_effective_lifecycle_policy_details).
    ///
    /// <p>A list of lifecycle policies applied to the OpenSearch Serverless indexes.</p>
    pub fn effective_lifecycle_policy_details(mut self, input: crate::types::EffectiveLifecyclePolicyDetail) -> Self {
        let mut v = self.effective_lifecycle_policy_details.unwrap_or_default();
        v.push(input);
        self.effective_lifecycle_policy_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of lifecycle policies applied to the OpenSearch Serverless indexes.</p>
    pub fn set_effective_lifecycle_policy_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyDetail>>,
    ) -> Self {
        self.effective_lifecycle_policy_details = input;
        self
    }
    /// <p>A list of lifecycle policies applied to the OpenSearch Serverless indexes.</p>
    pub fn get_effective_lifecycle_policy_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyDetail>> {
        &self.effective_lifecycle_policy_details
    }
    /// Appends an item to `effective_lifecycle_policy_error_details`.
    ///
    /// To override the contents of this collection use [`set_effective_lifecycle_policy_error_details`](Self::set_effective_lifecycle_policy_error_details).
    ///
    /// <p>A list of resources for which retrieval failed.</p>
    pub fn effective_lifecycle_policy_error_details(mut self, input: crate::types::EffectiveLifecyclePolicyErrorDetail) -> Self {
        let mut v = self.effective_lifecycle_policy_error_details.unwrap_or_default();
        v.push(input);
        self.effective_lifecycle_policy_error_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of resources for which retrieval failed.</p>
    pub fn set_effective_lifecycle_policy_error_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyErrorDetail>>,
    ) -> Self {
        self.effective_lifecycle_policy_error_details = input;
        self
    }
    /// <p>A list of resources for which retrieval failed.</p>
    pub fn get_effective_lifecycle_policy_error_details(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::EffectiveLifecyclePolicyErrorDetail>> {
        &self.effective_lifecycle_policy_error_details
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetEffectiveLifecyclePolicyOutput`](crate::operation::batch_get_effective_lifecycle_policy::BatchGetEffectiveLifecyclePolicyOutput).
    pub fn build(self) -> crate::operation::batch_get_effective_lifecycle_policy::BatchGetEffectiveLifecyclePolicyOutput {
        crate::operation::batch_get_effective_lifecycle_policy::BatchGetEffectiveLifecyclePolicyOutput {
            effective_lifecycle_policy_details: self.effective_lifecycle_policy_details,
            effective_lifecycle_policy_error_details: self.effective_lifecycle_policy_error_details,
            _request_id: self._request_id,
        }
    }
}
