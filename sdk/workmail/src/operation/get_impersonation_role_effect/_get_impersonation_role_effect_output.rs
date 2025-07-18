// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImpersonationRoleEffectOutput {
    /// <p>The impersonation role type.</p>
    pub r#type: ::std::option::Option<crate::types::ImpersonationRoleType>,
    /// <p><code></code>Effect of the impersonation role on the target user based on its rules. Available effects are <code>ALLOW</code> or <code>DENY</code>.</p>
    pub effect: ::std::option::Option<crate::types::AccessEffect>,
    /// <p>A list of the rules that match the input and produce the configured effect.</p>
    pub matched_rules: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationMatchedRule>>,
    _request_id: Option<String>,
}
impl GetImpersonationRoleEffectOutput {
    /// <p>The impersonation role type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ImpersonationRoleType> {
        self.r#type.as_ref()
    }
    /// <p><code></code>Effect of the impersonation role on the target user based on its rules. Available effects are <code>ALLOW</code> or <code>DENY</code>.</p>
    pub fn effect(&self) -> ::std::option::Option<&crate::types::AccessEffect> {
        self.effect.as_ref()
    }
    /// <p>A list of the rules that match the input and produce the configured effect.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.matched_rules.is_none()`.
    pub fn matched_rules(&self) -> &[crate::types::ImpersonationMatchedRule] {
        self.matched_rules.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetImpersonationRoleEffectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImpersonationRoleEffectOutput {
    /// Creates a new builder-style object to manufacture [`GetImpersonationRoleEffectOutput`](crate::operation::get_impersonation_role_effect::GetImpersonationRoleEffectOutput).
    pub fn builder() -> crate::operation::get_impersonation_role_effect::builders::GetImpersonationRoleEffectOutputBuilder {
        crate::operation::get_impersonation_role_effect::builders::GetImpersonationRoleEffectOutputBuilder::default()
    }
}

/// A builder for [`GetImpersonationRoleEffectOutput`](crate::operation::get_impersonation_role_effect::GetImpersonationRoleEffectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImpersonationRoleEffectOutputBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ImpersonationRoleType>,
    pub(crate) effect: ::std::option::Option<crate::types::AccessEffect>,
    pub(crate) matched_rules: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationMatchedRule>>,
    _request_id: Option<String>,
}
impl GetImpersonationRoleEffectOutputBuilder {
    /// <p>The impersonation role type.</p>
    pub fn r#type(mut self, input: crate::types::ImpersonationRoleType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The impersonation role type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ImpersonationRoleType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The impersonation role type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ImpersonationRoleType> {
        &self.r#type
    }
    /// <p><code></code>Effect of the impersonation role on the target user based on its rules. Available effects are <code>ALLOW</code> or <code>DENY</code>.</p>
    pub fn effect(mut self, input: crate::types::AccessEffect) -> Self {
        self.effect = ::std::option::Option::Some(input);
        self
    }
    /// <p><code></code>Effect of the impersonation role on the target user based on its rules. Available effects are <code>ALLOW</code> or <code>DENY</code>.</p>
    pub fn set_effect(mut self, input: ::std::option::Option<crate::types::AccessEffect>) -> Self {
        self.effect = input;
        self
    }
    /// <p><code></code>Effect of the impersonation role on the target user based on its rules. Available effects are <code>ALLOW</code> or <code>DENY</code>.</p>
    pub fn get_effect(&self) -> &::std::option::Option<crate::types::AccessEffect> {
        &self.effect
    }
    /// Appends an item to `matched_rules`.
    ///
    /// To override the contents of this collection use [`set_matched_rules`](Self::set_matched_rules).
    ///
    /// <p>A list of the rules that match the input and produce the configured effect.</p>
    pub fn matched_rules(mut self, input: crate::types::ImpersonationMatchedRule) -> Self {
        let mut v = self.matched_rules.unwrap_or_default();
        v.push(input);
        self.matched_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the rules that match the input and produce the configured effect.</p>
    pub fn set_matched_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationMatchedRule>>) -> Self {
        self.matched_rules = input;
        self
    }
    /// <p>A list of the rules that match the input and produce the configured effect.</p>
    pub fn get_matched_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImpersonationMatchedRule>> {
        &self.matched_rules
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImpersonationRoleEffectOutput`](crate::operation::get_impersonation_role_effect::GetImpersonationRoleEffectOutput).
    pub fn build(self) -> crate::operation::get_impersonation_role_effect::GetImpersonationRoleEffectOutput {
        crate::operation::get_impersonation_role_effect::GetImpersonationRoleEffectOutput {
            r#type: self.r#type,
            effect: self.effect,
            matched_rules: self.matched_rules,
            _request_id: self._request_id,
        }
    }
}
