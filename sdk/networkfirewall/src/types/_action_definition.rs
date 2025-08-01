// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A custom action to use in stateless rule actions settings. This is used in <code>CustomAction</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActionDefinition {
    /// <p>Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published.</p>
    /// <p>You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.</p>
    pub publish_metric_action: ::std::option::Option<crate::types::PublishMetricAction>,
}
impl ActionDefinition {
    /// <p>Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published.</p>
    /// <p>You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.</p>
    pub fn publish_metric_action(&self) -> ::std::option::Option<&crate::types::PublishMetricAction> {
        self.publish_metric_action.as_ref()
    }
}
impl ActionDefinition {
    /// Creates a new builder-style object to manufacture [`ActionDefinition`](crate::types::ActionDefinition).
    pub fn builder() -> crate::types::builders::ActionDefinitionBuilder {
        crate::types::builders::ActionDefinitionBuilder::default()
    }
}

/// A builder for [`ActionDefinition`](crate::types::ActionDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActionDefinitionBuilder {
    pub(crate) publish_metric_action: ::std::option::Option<crate::types::PublishMetricAction>,
}
impl ActionDefinitionBuilder {
    /// <p>Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published.</p>
    /// <p>You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.</p>
    pub fn publish_metric_action(mut self, input: crate::types::PublishMetricAction) -> Self {
        self.publish_metric_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published.</p>
    /// <p>You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.</p>
    pub fn set_publish_metric_action(mut self, input: ::std::option::Option<crate::types::PublishMetricAction>) -> Self {
        self.publish_metric_action = input;
        self
    }
    /// <p>Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published.</p>
    /// <p>You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.</p>
    pub fn get_publish_metric_action(&self) -> &::std::option::Option<crate::types::PublishMetricAction> {
        &self.publish_metric_action
    }
    /// Consumes the builder and constructs a [`ActionDefinition`](crate::types::ActionDefinition).
    pub fn build(self) -> crate::types::ActionDefinition {
        crate::types::ActionDefinition {
            publish_metric_action: self.publish_metric_action,
        }
    }
}
