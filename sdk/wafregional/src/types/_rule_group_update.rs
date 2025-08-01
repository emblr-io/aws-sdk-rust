// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>Specifies an <code>ActivatedRule</code> and indicates whether you want to add it to a <code>RuleGroup</code> or delete it from a <code>RuleGroup</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuleGroupUpdate {
    /// <p>Specify <code>INSERT</code> to add an <code>ActivatedRule</code> to a <code>RuleGroup</code>. Use <code>DELETE</code> to remove an <code>ActivatedRule</code> from a <code>RuleGroup</code>.</p>
    pub action: crate::types::ChangeAction,
    /// <p>The <code>ActivatedRule</code> object specifies a <code>Rule</code> that you want to insert or delete, the priority of the <code>Rule</code> in the <code>WebACL</code>, and the action that you want AWS WAF to take when a web request matches the <code>Rule</code> (<code>ALLOW</code>, <code>BLOCK</code>, or <code>COUNT</code>).</p>
    pub activated_rule: ::std::option::Option<crate::types::ActivatedRule>,
}
impl RuleGroupUpdate {
    /// <p>Specify <code>INSERT</code> to add an <code>ActivatedRule</code> to a <code>RuleGroup</code>. Use <code>DELETE</code> to remove an <code>ActivatedRule</code> from a <code>RuleGroup</code>.</p>
    pub fn action(&self) -> &crate::types::ChangeAction {
        &self.action
    }
    /// <p>The <code>ActivatedRule</code> object specifies a <code>Rule</code> that you want to insert or delete, the priority of the <code>Rule</code> in the <code>WebACL</code>, and the action that you want AWS WAF to take when a web request matches the <code>Rule</code> (<code>ALLOW</code>, <code>BLOCK</code>, or <code>COUNT</code>).</p>
    pub fn activated_rule(&self) -> ::std::option::Option<&crate::types::ActivatedRule> {
        self.activated_rule.as_ref()
    }
}
impl RuleGroupUpdate {
    /// Creates a new builder-style object to manufacture [`RuleGroupUpdate`](crate::types::RuleGroupUpdate).
    pub fn builder() -> crate::types::builders::RuleGroupUpdateBuilder {
        crate::types::builders::RuleGroupUpdateBuilder::default()
    }
}

/// A builder for [`RuleGroupUpdate`](crate::types::RuleGroupUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuleGroupUpdateBuilder {
    pub(crate) action: ::std::option::Option<crate::types::ChangeAction>,
    pub(crate) activated_rule: ::std::option::Option<crate::types::ActivatedRule>,
}
impl RuleGroupUpdateBuilder {
    /// <p>Specify <code>INSERT</code> to add an <code>ActivatedRule</code> to a <code>RuleGroup</code>. Use <code>DELETE</code> to remove an <code>ActivatedRule</code> from a <code>RuleGroup</code>.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::ChangeAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>INSERT</code> to add an <code>ActivatedRule</code> to a <code>RuleGroup</code>. Use <code>DELETE</code> to remove an <code>ActivatedRule</code> from a <code>RuleGroup</code>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ChangeAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specify <code>INSERT</code> to add an <code>ActivatedRule</code> to a <code>RuleGroup</code>. Use <code>DELETE</code> to remove an <code>ActivatedRule</code> from a <code>RuleGroup</code>.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ChangeAction> {
        &self.action
    }
    /// <p>The <code>ActivatedRule</code> object specifies a <code>Rule</code> that you want to insert or delete, the priority of the <code>Rule</code> in the <code>WebACL</code>, and the action that you want AWS WAF to take when a web request matches the <code>Rule</code> (<code>ALLOW</code>, <code>BLOCK</code>, or <code>COUNT</code>).</p>
    /// This field is required.
    pub fn activated_rule(mut self, input: crate::types::ActivatedRule) -> Self {
        self.activated_rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>ActivatedRule</code> object specifies a <code>Rule</code> that you want to insert or delete, the priority of the <code>Rule</code> in the <code>WebACL</code>, and the action that you want AWS WAF to take when a web request matches the <code>Rule</code> (<code>ALLOW</code>, <code>BLOCK</code>, or <code>COUNT</code>).</p>
    pub fn set_activated_rule(mut self, input: ::std::option::Option<crate::types::ActivatedRule>) -> Self {
        self.activated_rule = input;
        self
    }
    /// <p>The <code>ActivatedRule</code> object specifies a <code>Rule</code> that you want to insert or delete, the priority of the <code>Rule</code> in the <code>WebACL</code>, and the action that you want AWS WAF to take when a web request matches the <code>Rule</code> (<code>ALLOW</code>, <code>BLOCK</code>, or <code>COUNT</code>).</p>
    pub fn get_activated_rule(&self) -> &::std::option::Option<crate::types::ActivatedRule> {
        &self.activated_rule
    }
    /// Consumes the builder and constructs a [`RuleGroupUpdate`](crate::types::RuleGroupUpdate).
    /// This method will fail if any of the following fields are not set:
    /// - [`action`](crate::types::builders::RuleGroupUpdateBuilder::action)
    pub fn build(self) -> ::std::result::Result<crate::types::RuleGroupUpdate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RuleGroupUpdate {
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building RuleGroupUpdate",
                )
            })?,
            activated_rule: self.activated_rule,
        })
    }
}
