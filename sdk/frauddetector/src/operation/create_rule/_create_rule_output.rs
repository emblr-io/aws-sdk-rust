// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRuleOutput {
    /// <p>The created rule.</p>
    pub rule: ::std::option::Option<crate::types::Rule>,
    _request_id: Option<String>,
}
impl CreateRuleOutput {
    /// <p>The created rule.</p>
    pub fn rule(&self) -> ::std::option::Option<&crate::types::Rule> {
        self.rule.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRuleOutput {
    /// Creates a new builder-style object to manufacture [`CreateRuleOutput`](crate::operation::create_rule::CreateRuleOutput).
    pub fn builder() -> crate::operation::create_rule::builders::CreateRuleOutputBuilder {
        crate::operation::create_rule::builders::CreateRuleOutputBuilder::default()
    }
}

/// A builder for [`CreateRuleOutput`](crate::operation::create_rule::CreateRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRuleOutputBuilder {
    pub(crate) rule: ::std::option::Option<crate::types::Rule>,
    _request_id: Option<String>,
}
impl CreateRuleOutputBuilder {
    /// <p>The created rule.</p>
    pub fn rule(mut self, input: crate::types::Rule) -> Self {
        self.rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The created rule.</p>
    pub fn set_rule(mut self, input: ::std::option::Option<crate::types::Rule>) -> Self {
        self.rule = input;
        self
    }
    /// <p>The created rule.</p>
    pub fn get_rule(&self) -> &::std::option::Option<crate::types::Rule> {
        &self.rule
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateRuleOutput`](crate::operation::create_rule::CreateRuleOutput).
    pub fn build(self) -> crate::operation::create_rule::CreateRuleOutput {
        crate::operation::create_rule::CreateRuleOutput {
            rule: self.rule,
            _request_id: self._request_id,
        }
    }
}
