// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An assertion rule enforces that, when you change a routing control state, that the criteria that you set in the rule configuration is met. Otherwise, the change to the routing control is not accepted. For example, the criteria might be that at least one routing control state is On after the transaction so that traffic continues to flow to at least one cell for the application. This ensures that you avoid a fail-open scenario.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssertionRule {
    /// <p>The routing controls that are part of transactions that are evaluated to determine if a request to change a routing control state is allowed. For example, you might include three routing controls, one for each of three Amazon Web Services Regions.</p>
    pub asserted_controls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of the control panel.</p>
    pub control_panel_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of the assertion rule. You can use any non-white space character in the name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The criteria that you set for specific assertion routing controls (AssertedControls) that designate how many routing control states must be ON as the result of a transaction. For example, if you have three assertion routing controls, you might specify ATLEAST 2 for your rule configuration. This means that at least two assertion routing control states must be ON, so that at least two Amazon Web Services Regions have traffic flowing to them.</p>
    pub rule_config: ::std::option::Option<crate::types::RuleConfig>,
    /// <p>The Amazon Resource Name (ARN) of the assertion rule.</p>
    pub safety_rule_arn: ::std::option::Option<::std::string::String>,
    /// <p>The deployment status of an assertion rule. Status can be one of the following: PENDING, DEPLOYED, PENDING_DELETION.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>An evaluation period, in milliseconds (ms), during which any request against the target routing controls will fail. This helps prevent "flapping" of state. The wait period is 5000 ms by default, but you can choose a custom value.</p>
    pub wait_period_ms: ::std::option::Option<i32>,
    /// <p>The Amazon Web Services account ID of the assertion rule owner.</p>
    pub owner: ::std::option::Option<::std::string::String>,
}
impl AssertionRule {
    /// <p>The routing controls that are part of transactions that are evaluated to determine if a request to change a routing control state is allowed. For example, you might include three routing controls, one for each of three Amazon Web Services Regions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.asserted_controls.is_none()`.
    pub fn asserted_controls(&self) -> &[::std::string::String] {
        self.asserted_controls.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of the control panel.</p>
    pub fn control_panel_arn(&self) -> ::std::option::Option<&str> {
        self.control_panel_arn.as_deref()
    }
    /// <p>Name of the assertion rule. You can use any non-white space character in the name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The criteria that you set for specific assertion routing controls (AssertedControls) that designate how many routing control states must be ON as the result of a transaction. For example, if you have three assertion routing controls, you might specify ATLEAST 2 for your rule configuration. This means that at least two assertion routing control states must be ON, so that at least two Amazon Web Services Regions have traffic flowing to them.</p>
    pub fn rule_config(&self) -> ::std::option::Option<&crate::types::RuleConfig> {
        self.rule_config.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the assertion rule.</p>
    pub fn safety_rule_arn(&self) -> ::std::option::Option<&str> {
        self.safety_rule_arn.as_deref()
    }
    /// <p>The deployment status of an assertion rule. Status can be one of the following: PENDING, DEPLOYED, PENDING_DELETION.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>An evaluation period, in milliseconds (ms), during which any request against the target routing controls will fail. This helps prevent "flapping" of state. The wait period is 5000 ms by default, but you can choose a custom value.</p>
    pub fn wait_period_ms(&self) -> ::std::option::Option<i32> {
        self.wait_period_ms
    }
    /// <p>The Amazon Web Services account ID of the assertion rule owner.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
}
impl AssertionRule {
    /// Creates a new builder-style object to manufacture [`AssertionRule`](crate::types::AssertionRule).
    pub fn builder() -> crate::types::builders::AssertionRuleBuilder {
        crate::types::builders::AssertionRuleBuilder::default()
    }
}

/// A builder for [`AssertionRule`](crate::types::AssertionRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssertionRuleBuilder {
    pub(crate) asserted_controls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) control_panel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) rule_config: ::std::option::Option<crate::types::RuleConfig>,
    pub(crate) safety_rule_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) wait_period_ms: ::std::option::Option<i32>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
}
impl AssertionRuleBuilder {
    /// Appends an item to `asserted_controls`.
    ///
    /// To override the contents of this collection use [`set_asserted_controls`](Self::set_asserted_controls).
    ///
    /// <p>The routing controls that are part of transactions that are evaluated to determine if a request to change a routing control state is allowed. For example, you might include three routing controls, one for each of three Amazon Web Services Regions.</p>
    pub fn asserted_controls(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.asserted_controls.unwrap_or_default();
        v.push(input.into());
        self.asserted_controls = ::std::option::Option::Some(v);
        self
    }
    /// <p>The routing controls that are part of transactions that are evaluated to determine if a request to change a routing control state is allowed. For example, you might include three routing controls, one for each of three Amazon Web Services Regions.</p>
    pub fn set_asserted_controls(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.asserted_controls = input;
        self
    }
    /// <p>The routing controls that are part of transactions that are evaluated to determine if a request to change a routing control state is allowed. For example, you might include three routing controls, one for each of three Amazon Web Services Regions.</p>
    pub fn get_asserted_controls(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.asserted_controls
    }
    /// <p>The Amazon Resource Name (ARN) of the control panel.</p>
    /// This field is required.
    pub fn control_panel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_panel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the control panel.</p>
    pub fn set_control_panel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_panel_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the control panel.</p>
    pub fn get_control_panel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_panel_arn
    }
    /// <p>Name of the assertion rule. You can use any non-white space character in the name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the assertion rule. You can use any non-white space character in the name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the assertion rule. You can use any non-white space character in the name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The criteria that you set for specific assertion routing controls (AssertedControls) that designate how many routing control states must be ON as the result of a transaction. For example, if you have three assertion routing controls, you might specify ATLEAST 2 for your rule configuration. This means that at least two assertion routing control states must be ON, so that at least two Amazon Web Services Regions have traffic flowing to them.</p>
    /// This field is required.
    pub fn rule_config(mut self, input: crate::types::RuleConfig) -> Self {
        self.rule_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The criteria that you set for specific assertion routing controls (AssertedControls) that designate how many routing control states must be ON as the result of a transaction. For example, if you have three assertion routing controls, you might specify ATLEAST 2 for your rule configuration. This means that at least two assertion routing control states must be ON, so that at least two Amazon Web Services Regions have traffic flowing to them.</p>
    pub fn set_rule_config(mut self, input: ::std::option::Option<crate::types::RuleConfig>) -> Self {
        self.rule_config = input;
        self
    }
    /// <p>The criteria that you set for specific assertion routing controls (AssertedControls) that designate how many routing control states must be ON as the result of a transaction. For example, if you have three assertion routing controls, you might specify ATLEAST 2 for your rule configuration. This means that at least two assertion routing control states must be ON, so that at least two Amazon Web Services Regions have traffic flowing to them.</p>
    pub fn get_rule_config(&self) -> &::std::option::Option<crate::types::RuleConfig> {
        &self.rule_config
    }
    /// <p>The Amazon Resource Name (ARN) of the assertion rule.</p>
    /// This field is required.
    pub fn safety_rule_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.safety_rule_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the assertion rule.</p>
    pub fn set_safety_rule_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.safety_rule_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the assertion rule.</p>
    pub fn get_safety_rule_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.safety_rule_arn
    }
    /// <p>The deployment status of an assertion rule. Status can be one of the following: PENDING, DEPLOYED, PENDING_DELETION.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deployment status of an assertion rule. Status can be one of the following: PENDING, DEPLOYED, PENDING_DELETION.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The deployment status of an assertion rule. Status can be one of the following: PENDING, DEPLOYED, PENDING_DELETION.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>An evaluation period, in milliseconds (ms), during which any request against the target routing controls will fail. This helps prevent "flapping" of state. The wait period is 5000 ms by default, but you can choose a custom value.</p>
    /// This field is required.
    pub fn wait_period_ms(mut self, input: i32) -> Self {
        self.wait_period_ms = ::std::option::Option::Some(input);
        self
    }
    /// <p>An evaluation period, in milliseconds (ms), during which any request against the target routing controls will fail. This helps prevent "flapping" of state. The wait period is 5000 ms by default, but you can choose a custom value.</p>
    pub fn set_wait_period_ms(mut self, input: ::std::option::Option<i32>) -> Self {
        self.wait_period_ms = input;
        self
    }
    /// <p>An evaluation period, in milliseconds (ms), during which any request against the target routing controls will fail. This helps prevent "flapping" of state. The wait period is 5000 ms by default, but you can choose a custom value.</p>
    pub fn get_wait_period_ms(&self) -> &::std::option::Option<i32> {
        &self.wait_period_ms
    }
    /// <p>The Amazon Web Services account ID of the assertion rule owner.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the assertion rule owner.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the assertion rule owner.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// Consumes the builder and constructs a [`AssertionRule`](crate::types::AssertionRule).
    pub fn build(self) -> crate::types::AssertionRule {
        crate::types::AssertionRule {
            asserted_controls: self.asserted_controls,
            control_panel_arn: self.control_panel_arn,
            name: self.name,
            rule_config: self.rule_config,
            safety_rule_arn: self.safety_rule_arn,
            status: self.status,
            wait_period_ms: self.wait_period_ms,
            owner: self.owner,
        }
    }
}
