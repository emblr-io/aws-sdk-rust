// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the queue and channel for which priority and delay can be set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RoutingProfileQueueConfig {
    /// <p>Contains information about a queue resource.</p>
    pub queue_reference: ::std::option::Option<crate::types::RoutingProfileQueueReference>,
    /// <p>The order in which contacts are to be handled for the queue. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a>.</p>
    pub priority: i32,
    /// <p>The delay, in seconds, a contact should be in the queue before they are routed to an available agent. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a> in the <i>Amazon Connect Administrator Guide</i>.</p>
    pub delay: i32,
}
impl RoutingProfileQueueConfig {
    /// <p>Contains information about a queue resource.</p>
    pub fn queue_reference(&self) -> ::std::option::Option<&crate::types::RoutingProfileQueueReference> {
        self.queue_reference.as_ref()
    }
    /// <p>The order in which contacts are to be handled for the queue. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a>.</p>
    pub fn priority(&self) -> i32 {
        self.priority
    }
    /// <p>The delay, in seconds, a contact should be in the queue before they are routed to an available agent. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a> in the <i>Amazon Connect Administrator Guide</i>.</p>
    pub fn delay(&self) -> i32 {
        self.delay
    }
}
impl RoutingProfileQueueConfig {
    /// Creates a new builder-style object to manufacture [`RoutingProfileQueueConfig`](crate::types::RoutingProfileQueueConfig).
    pub fn builder() -> crate::types::builders::RoutingProfileQueueConfigBuilder {
        crate::types::builders::RoutingProfileQueueConfigBuilder::default()
    }
}

/// A builder for [`RoutingProfileQueueConfig`](crate::types::RoutingProfileQueueConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RoutingProfileQueueConfigBuilder {
    pub(crate) queue_reference: ::std::option::Option<crate::types::RoutingProfileQueueReference>,
    pub(crate) priority: ::std::option::Option<i32>,
    pub(crate) delay: ::std::option::Option<i32>,
}
impl RoutingProfileQueueConfigBuilder {
    /// <p>Contains information about a queue resource.</p>
    /// This field is required.
    pub fn queue_reference(mut self, input: crate::types::RoutingProfileQueueReference) -> Self {
        self.queue_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about a queue resource.</p>
    pub fn set_queue_reference(mut self, input: ::std::option::Option<crate::types::RoutingProfileQueueReference>) -> Self {
        self.queue_reference = input;
        self
    }
    /// <p>Contains information about a queue resource.</p>
    pub fn get_queue_reference(&self) -> &::std::option::Option<crate::types::RoutingProfileQueueReference> {
        &self.queue_reference
    }
    /// <p>The order in which contacts are to be handled for the queue. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a>.</p>
    /// This field is required.
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order in which contacts are to be handled for the queue. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a>.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The order in which contacts are to be handled for the queue. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a>.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// <p>The delay, in seconds, a contact should be in the queue before they are routed to an available agent. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a> in the <i>Amazon Connect Administrator Guide</i>.</p>
    /// This field is required.
    pub fn delay(mut self, input: i32) -> Self {
        self.delay = ::std::option::Option::Some(input);
        self
    }
    /// <p>The delay, in seconds, a contact should be in the queue before they are routed to an available agent. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a> in the <i>Amazon Connect Administrator Guide</i>.</p>
    pub fn set_delay(mut self, input: ::std::option::Option<i32>) -> Self {
        self.delay = input;
        self
    }
    /// <p>The delay, in seconds, a contact should be in the queue before they are routed to an available agent. For more information, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/concepts-routing-profiles-priority.html">Queues: priority and delay</a> in the <i>Amazon Connect Administrator Guide</i>.</p>
    pub fn get_delay(&self) -> &::std::option::Option<i32> {
        &self.delay
    }
    /// Consumes the builder and constructs a [`RoutingProfileQueueConfig`](crate::types::RoutingProfileQueueConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`priority`](crate::types::builders::RoutingProfileQueueConfigBuilder::priority)
    /// - [`delay`](crate::types::builders::RoutingProfileQueueConfigBuilder::delay)
    pub fn build(self) -> ::std::result::Result<crate::types::RoutingProfileQueueConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RoutingProfileQueueConfig {
            queue_reference: self.queue_reference,
            priority: self.priority.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "priority",
                    "priority was not specified but it is required when building RoutingProfileQueueConfig",
                )
            })?,
            delay: self.delay.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "delay",
                    "delay was not specified but it is required when building RoutingProfileQueueConfig",
                )
            })?,
        })
    }
}
