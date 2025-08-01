// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an event that occurred during an flow execution. This is a union type that can contain one of several event types, such as node input and output events; flow input and output events; condition node result events, or failure events.</p><note>
/// <p>Flow executions is in preview release for Amazon Bedrock and is subject to change.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum FlowExecutionEvent {
    /// <p>Contains information about a condition evaluation result during the flow execution. This event is generated when a condition node in the flow evaluates its conditions.</p>
    ConditionResultEvent(crate::types::ConditionResultEvent),
    /// <p>Contains information about a failure that occurred at the flow level during execution.</p>
    FlowFailureEvent(crate::types::FlowFailureEvent),
    /// <p>Contains information about the inputs provided to the flow at the start of execution.</p>
    FlowInputEvent(crate::types::FlowExecutionInputEvent),
    /// <p>Contains information about the outputs produced by the flow at the end of execution.</p>
    FlowOutputEvent(crate::types::FlowExecutionOutputEvent),
    /// <p>Contains information about a failure that occurred at a specific node during execution.</p>
    NodeFailureEvent(crate::types::NodeFailureEvent),
    /// <p>Contains information about the inputs provided to a specific node during execution.</p>
    NodeInputEvent(crate::types::NodeInputEvent),
    /// <p>Contains information about the outputs produced by a specific node during execution.</p>
    NodeOutputEvent(crate::types::NodeOutputEvent),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl FlowExecutionEvent {
    /// Tries to convert the enum instance into [`ConditionResultEvent`](crate::types::FlowExecutionEvent::ConditionResultEvent), extracting the inner [`ConditionResultEvent`](crate::types::ConditionResultEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_condition_result_event(&self) -> ::std::result::Result<&crate::types::ConditionResultEvent, &Self> {
        if let FlowExecutionEvent::ConditionResultEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ConditionResultEvent`](crate::types::FlowExecutionEvent::ConditionResultEvent).
    pub fn is_condition_result_event(&self) -> bool {
        self.as_condition_result_event().is_ok()
    }
    /// Tries to convert the enum instance into [`FlowFailureEvent`](crate::types::FlowExecutionEvent::FlowFailureEvent), extracting the inner [`FlowFailureEvent`](crate::types::FlowFailureEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_flow_failure_event(&self) -> ::std::result::Result<&crate::types::FlowFailureEvent, &Self> {
        if let FlowExecutionEvent::FlowFailureEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FlowFailureEvent`](crate::types::FlowExecutionEvent::FlowFailureEvent).
    pub fn is_flow_failure_event(&self) -> bool {
        self.as_flow_failure_event().is_ok()
    }
    /// Tries to convert the enum instance into [`FlowInputEvent`](crate::types::FlowExecutionEvent::FlowInputEvent), extracting the inner [`FlowExecutionInputEvent`](crate::types::FlowExecutionInputEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_flow_input_event(&self) -> ::std::result::Result<&crate::types::FlowExecutionInputEvent, &Self> {
        if let FlowExecutionEvent::FlowInputEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FlowInputEvent`](crate::types::FlowExecutionEvent::FlowInputEvent).
    pub fn is_flow_input_event(&self) -> bool {
        self.as_flow_input_event().is_ok()
    }
    /// Tries to convert the enum instance into [`FlowOutputEvent`](crate::types::FlowExecutionEvent::FlowOutputEvent), extracting the inner [`FlowExecutionOutputEvent`](crate::types::FlowExecutionOutputEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_flow_output_event(&self) -> ::std::result::Result<&crate::types::FlowExecutionOutputEvent, &Self> {
        if let FlowExecutionEvent::FlowOutputEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FlowOutputEvent`](crate::types::FlowExecutionEvent::FlowOutputEvent).
    pub fn is_flow_output_event(&self) -> bool {
        self.as_flow_output_event().is_ok()
    }
    /// Tries to convert the enum instance into [`NodeFailureEvent`](crate::types::FlowExecutionEvent::NodeFailureEvent), extracting the inner [`NodeFailureEvent`](crate::types::NodeFailureEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_node_failure_event(&self) -> ::std::result::Result<&crate::types::NodeFailureEvent, &Self> {
        if let FlowExecutionEvent::NodeFailureEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NodeFailureEvent`](crate::types::FlowExecutionEvent::NodeFailureEvent).
    pub fn is_node_failure_event(&self) -> bool {
        self.as_node_failure_event().is_ok()
    }
    /// Tries to convert the enum instance into [`NodeInputEvent`](crate::types::FlowExecutionEvent::NodeInputEvent), extracting the inner [`NodeInputEvent`](crate::types::NodeInputEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_node_input_event(&self) -> ::std::result::Result<&crate::types::NodeInputEvent, &Self> {
        if let FlowExecutionEvent::NodeInputEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NodeInputEvent`](crate::types::FlowExecutionEvent::NodeInputEvent).
    pub fn is_node_input_event(&self) -> bool {
        self.as_node_input_event().is_ok()
    }
    /// Tries to convert the enum instance into [`NodeOutputEvent`](crate::types::FlowExecutionEvent::NodeOutputEvent), extracting the inner [`NodeOutputEvent`](crate::types::NodeOutputEvent).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_node_output_event(&self) -> ::std::result::Result<&crate::types::NodeOutputEvent, &Self> {
        if let FlowExecutionEvent::NodeOutputEvent(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NodeOutputEvent`](crate::types::FlowExecutionEvent::NodeOutputEvent).
    pub fn is_node_output_event(&self) -> bool {
        self.as_node_output_event().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for FlowExecutionEvent {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            FlowExecutionEvent::ConditionResultEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::FlowFailureEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::FlowInputEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::FlowOutputEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::NodeFailureEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::NodeInputEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::NodeOutputEvent(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            FlowExecutionEvent::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
