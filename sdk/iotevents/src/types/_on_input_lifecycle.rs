// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OnInputLifecycle {
    /// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
    pub events: ::std::option::Option<::std::vec::Vec<crate::types::Event>>,
    /// <p>Specifies the actions performed, and the next state entered, when a <code>condition</code> evaluates to TRUE.</p>
    pub transition_events: ::std::option::Option<::std::vec::Vec<crate::types::TransitionEvent>>,
}
impl OnInputLifecycle {
    /// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.events.is_none()`.
    pub fn events(&self) -> &[crate::types::Event] {
        self.events.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the actions performed, and the next state entered, when a <code>condition</code> evaluates to TRUE.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.transition_events.is_none()`.
    pub fn transition_events(&self) -> &[crate::types::TransitionEvent] {
        self.transition_events.as_deref().unwrap_or_default()
    }
}
impl OnInputLifecycle {
    /// Creates a new builder-style object to manufacture [`OnInputLifecycle`](crate::types::OnInputLifecycle).
    pub fn builder() -> crate::types::builders::OnInputLifecycleBuilder {
        crate::types::builders::OnInputLifecycleBuilder::default()
    }
}

/// A builder for [`OnInputLifecycle`](crate::types::OnInputLifecycle).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OnInputLifecycleBuilder {
    pub(crate) events: ::std::option::Option<::std::vec::Vec<crate::types::Event>>,
    pub(crate) transition_events: ::std::option::Option<::std::vec::Vec<crate::types::TransitionEvent>>,
}
impl OnInputLifecycleBuilder {
    /// Appends an item to `events`.
    ///
    /// To override the contents of this collection use [`set_events`](Self::set_events).
    ///
    /// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
    pub fn events(mut self, input: crate::types::Event) -> Self {
        let mut v = self.events.unwrap_or_default();
        v.push(input);
        self.events = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
    pub fn set_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Event>>) -> Self {
        self.events = input;
        self
    }
    /// <p>Specifies the actions performed when the <code>condition</code> evaluates to TRUE.</p>
    pub fn get_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Event>> {
        &self.events
    }
    /// Appends an item to `transition_events`.
    ///
    /// To override the contents of this collection use [`set_transition_events`](Self::set_transition_events).
    ///
    /// <p>Specifies the actions performed, and the next state entered, when a <code>condition</code> evaluates to TRUE.</p>
    pub fn transition_events(mut self, input: crate::types::TransitionEvent) -> Self {
        let mut v = self.transition_events.unwrap_or_default();
        v.push(input);
        self.transition_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the actions performed, and the next state entered, when a <code>condition</code> evaluates to TRUE.</p>
    pub fn set_transition_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TransitionEvent>>) -> Self {
        self.transition_events = input;
        self
    }
    /// <p>Specifies the actions performed, and the next state entered, when a <code>condition</code> evaluates to TRUE.</p>
    pub fn get_transition_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TransitionEvent>> {
        &self.transition_events
    }
    /// Consumes the builder and constructs a [`OnInputLifecycle`](crate::types::OnInputLifecycle).
    pub fn build(self) -> crate::types::OnInputLifecycle {
        crate::types::OnInputLifecycle {
            events: self.events,
            transition_events: self.transition_events,
        }
    }
}
