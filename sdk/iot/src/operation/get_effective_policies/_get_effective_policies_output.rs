// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEffectivePoliciesOutput {
    /// <p>The effective policies.</p>
    pub effective_policies: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePolicy>>,
    _request_id: Option<String>,
}
impl GetEffectivePoliciesOutput {
    /// <p>The effective policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.effective_policies.is_none()`.
    pub fn effective_policies(&self) -> &[crate::types::EffectivePolicy] {
        self.effective_policies.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetEffectivePoliciesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEffectivePoliciesOutput {
    /// Creates a new builder-style object to manufacture [`GetEffectivePoliciesOutput`](crate::operation::get_effective_policies::GetEffectivePoliciesOutput).
    pub fn builder() -> crate::operation::get_effective_policies::builders::GetEffectivePoliciesOutputBuilder {
        crate::operation::get_effective_policies::builders::GetEffectivePoliciesOutputBuilder::default()
    }
}

/// A builder for [`GetEffectivePoliciesOutput`](crate::operation::get_effective_policies::GetEffectivePoliciesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEffectivePoliciesOutputBuilder {
    pub(crate) effective_policies: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePolicy>>,
    _request_id: Option<String>,
}
impl GetEffectivePoliciesOutputBuilder {
    /// Appends an item to `effective_policies`.
    ///
    /// To override the contents of this collection use [`set_effective_policies`](Self::set_effective_policies).
    ///
    /// <p>The effective policies.</p>
    pub fn effective_policies(mut self, input: crate::types::EffectivePolicy) -> Self {
        let mut v = self.effective_policies.unwrap_or_default();
        v.push(input);
        self.effective_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The effective policies.</p>
    pub fn set_effective_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EffectivePolicy>>) -> Self {
        self.effective_policies = input;
        self
    }
    /// <p>The effective policies.</p>
    pub fn get_effective_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EffectivePolicy>> {
        &self.effective_policies
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetEffectivePoliciesOutput`](crate::operation::get_effective_policies::GetEffectivePoliciesOutput).
    pub fn build(self) -> crate::operation::get_effective_policies::GetEffectivePoliciesOutput {
        crate::operation::get_effective_policies::GetEffectivePoliciesOutput {
            effective_policies: self.effective_policies,
            _request_id: self._request_id,
        }
    }
}
