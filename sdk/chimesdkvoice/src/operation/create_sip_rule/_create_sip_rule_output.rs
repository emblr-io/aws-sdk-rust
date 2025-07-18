// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSipRuleOutput {
    /// <p>The SIP rule information, including the rule ID, triggers, and target applications.</p>
    pub sip_rule: ::std::option::Option<crate::types::SipRule>,
    _request_id: Option<String>,
}
impl CreateSipRuleOutput {
    /// <p>The SIP rule information, including the rule ID, triggers, and target applications.</p>
    pub fn sip_rule(&self) -> ::std::option::Option<&crate::types::SipRule> {
        self.sip_rule.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSipRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSipRuleOutput {
    /// Creates a new builder-style object to manufacture [`CreateSipRuleOutput`](crate::operation::create_sip_rule::CreateSipRuleOutput).
    pub fn builder() -> crate::operation::create_sip_rule::builders::CreateSipRuleOutputBuilder {
        crate::operation::create_sip_rule::builders::CreateSipRuleOutputBuilder::default()
    }
}

/// A builder for [`CreateSipRuleOutput`](crate::operation::create_sip_rule::CreateSipRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSipRuleOutputBuilder {
    pub(crate) sip_rule: ::std::option::Option<crate::types::SipRule>,
    _request_id: Option<String>,
}
impl CreateSipRuleOutputBuilder {
    /// <p>The SIP rule information, including the rule ID, triggers, and target applications.</p>
    pub fn sip_rule(mut self, input: crate::types::SipRule) -> Self {
        self.sip_rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The SIP rule information, including the rule ID, triggers, and target applications.</p>
    pub fn set_sip_rule(mut self, input: ::std::option::Option<crate::types::SipRule>) -> Self {
        self.sip_rule = input;
        self
    }
    /// <p>The SIP rule information, including the rule ID, triggers, and target applications.</p>
    pub fn get_sip_rule(&self) -> &::std::option::Option<crate::types::SipRule> {
        &self.sip_rule
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSipRuleOutput`](crate::operation::create_sip_rule::CreateSipRuleOutput).
    pub fn build(self) -> crate::operation::create_sip_rule::CreateSipRuleOutput {
        crate::operation::create_sip_rule::CreateSipRuleOutput {
            sip_rule: self.sip_rule,
            _request_id: self._request_id,
        }
    }
}
