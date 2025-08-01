// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRuleInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique name for the rule.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The event source to trigger the rule.</p>
    pub trigger_event_source: ::std::option::Option<crate::types::RuleTriggerEventSource>,
    /// <p>The conditions of the rule.</p>
    pub function: ::std::option::Option<::std::string::String>,
    /// <p>A list of actions to be run when the rule is triggered.</p>
    pub actions: ::std::option::Option<::std::vec::Vec<crate::types::RuleAction>>,
    /// <p>The publish status of the rule.</p>
    pub publish_status: ::std::option::Option<crate::types::RulePublishStatus>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateRuleInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>A unique name for the rule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The event source to trigger the rule.</p>
    pub fn trigger_event_source(&self) -> ::std::option::Option<&crate::types::RuleTriggerEventSource> {
        self.trigger_event_source.as_ref()
    }
    /// <p>The conditions of the rule.</p>
    pub fn function(&self) -> ::std::option::Option<&str> {
        self.function.as_deref()
    }
    /// <p>A list of actions to be run when the rule is triggered.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actions.is_none()`.
    pub fn actions(&self) -> &[crate::types::RuleAction] {
        self.actions.as_deref().unwrap_or_default()
    }
    /// <p>The publish status of the rule.</p>
    pub fn publish_status(&self) -> ::std::option::Option<&crate::types::RulePublishStatus> {
        self.publish_status.as_ref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateRuleInput {
    /// Creates a new builder-style object to manufacture [`CreateRuleInput`](crate::operation::create_rule::CreateRuleInput).
    pub fn builder() -> crate::operation::create_rule::builders::CreateRuleInputBuilder {
        crate::operation::create_rule::builders::CreateRuleInputBuilder::default()
    }
}

/// A builder for [`CreateRuleInput`](crate::operation::create_rule::CreateRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRuleInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) trigger_event_source: ::std::option::Option<crate::types::RuleTriggerEventSource>,
    pub(crate) function: ::std::option::Option<::std::string::String>,
    pub(crate) actions: ::std::option::Option<::std::vec::Vec<crate::types::RuleAction>>,
    pub(crate) publish_status: ::std::option::Option<crate::types::RulePublishStatus>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateRuleInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>A unique name for the rule.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique name for the rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A unique name for the rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The event source to trigger the rule.</p>
    /// This field is required.
    pub fn trigger_event_source(mut self, input: crate::types::RuleTriggerEventSource) -> Self {
        self.trigger_event_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The event source to trigger the rule.</p>
    pub fn set_trigger_event_source(mut self, input: ::std::option::Option<crate::types::RuleTriggerEventSource>) -> Self {
        self.trigger_event_source = input;
        self
    }
    /// <p>The event source to trigger the rule.</p>
    pub fn get_trigger_event_source(&self) -> &::std::option::Option<crate::types::RuleTriggerEventSource> {
        &self.trigger_event_source
    }
    /// <p>The conditions of the rule.</p>
    /// This field is required.
    pub fn function(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The conditions of the rule.</p>
    pub fn set_function(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function = input;
        self
    }
    /// <p>The conditions of the rule.</p>
    pub fn get_function(&self) -> &::std::option::Option<::std::string::String> {
        &self.function
    }
    /// Appends an item to `actions`.
    ///
    /// To override the contents of this collection use [`set_actions`](Self::set_actions).
    ///
    /// <p>A list of actions to be run when the rule is triggered.</p>
    pub fn actions(mut self, input: crate::types::RuleAction) -> Self {
        let mut v = self.actions.unwrap_or_default();
        v.push(input);
        self.actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of actions to be run when the rule is triggered.</p>
    pub fn set_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RuleAction>>) -> Self {
        self.actions = input;
        self
    }
    /// <p>A list of actions to be run when the rule is triggered.</p>
    pub fn get_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RuleAction>> {
        &self.actions
    }
    /// <p>The publish status of the rule.</p>
    /// This field is required.
    pub fn publish_status(mut self, input: crate::types::RulePublishStatus) -> Self {
        self.publish_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The publish status of the rule.</p>
    pub fn set_publish_status(mut self, input: ::std::option::Option<crate::types::RulePublishStatus>) -> Self {
        self.publish_status = input;
        self
    }
    /// <p>The publish status of the rule.</p>
    pub fn get_publish_status(&self) -> &::std::option::Option<crate::types::RulePublishStatus> {
        &self.publish_status
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If not provided, the Amazon Web Services SDK populates this field. For more information about idempotency, see <a href="https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/">Making retries safe with idempotent APIs</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateRuleInput`](crate::operation::create_rule::CreateRuleInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_rule::CreateRuleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_rule::CreateRuleInput {
            instance_id: self.instance_id,
            name: self.name,
            trigger_event_source: self.trigger_event_source,
            function: self.function,
            actions: self.actions,
            publish_status: self.publish_status,
            client_token: self.client_token,
        })
    }
}
