// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The trace details used in the Guardrail.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GuardrailTrace {
    /// <p>The trace action details used with the Guardrail.</p>
    pub action: ::std::option::Option<crate::types::GuardrailAction>,
    /// <p>The details of the trace Id used in the Guardrail Trace.</p>
    pub trace_id: ::std::option::Option<::std::string::String>,
    /// <p>The details of the input assessments used in the Guardrail Trace.</p>
    pub input_assessments: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>,
    /// <p>The details of the output assessments used in the Guardrail Trace.</p>
    pub output_assessments: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>,
    /// <p>Contains information about the Guardrail output.</p>
    pub metadata: ::std::option::Option<crate::types::Metadata>,
}
impl GuardrailTrace {
    /// <p>The trace action details used with the Guardrail.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::GuardrailAction> {
        self.action.as_ref()
    }
    /// <p>The details of the trace Id used in the Guardrail Trace.</p>
    pub fn trace_id(&self) -> ::std::option::Option<&str> {
        self.trace_id.as_deref()
    }
    /// <p>The details of the input assessments used in the Guardrail Trace.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.input_assessments.is_none()`.
    pub fn input_assessments(&self) -> &[crate::types::GuardrailAssessment] {
        self.input_assessments.as_deref().unwrap_or_default()
    }
    /// <p>The details of the output assessments used in the Guardrail Trace.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.output_assessments.is_none()`.
    pub fn output_assessments(&self) -> &[crate::types::GuardrailAssessment] {
        self.output_assessments.as_deref().unwrap_or_default()
    }
    /// <p>Contains information about the Guardrail output.</p>
    pub fn metadata(&self) -> ::std::option::Option<&crate::types::Metadata> {
        self.metadata.as_ref()
    }
}
impl ::std::fmt::Debug for GuardrailTrace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GuardrailTrace");
        formatter.field("action", &"*** Sensitive Data Redacted ***");
        formatter.field("trace_id", &"*** Sensitive Data Redacted ***");
        formatter.field("input_assessments", &"*** Sensitive Data Redacted ***");
        formatter.field("output_assessments", &"*** Sensitive Data Redacted ***");
        formatter.field("metadata", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl GuardrailTrace {
    /// Creates a new builder-style object to manufacture [`GuardrailTrace`](crate::types::GuardrailTrace).
    pub fn builder() -> crate::types::builders::GuardrailTraceBuilder {
        crate::types::builders::GuardrailTraceBuilder::default()
    }
}

/// A builder for [`GuardrailTrace`](crate::types::GuardrailTrace).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GuardrailTraceBuilder {
    pub(crate) action: ::std::option::Option<crate::types::GuardrailAction>,
    pub(crate) trace_id: ::std::option::Option<::std::string::String>,
    pub(crate) input_assessments: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>,
    pub(crate) output_assessments: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>,
    pub(crate) metadata: ::std::option::Option<crate::types::Metadata>,
}
impl GuardrailTraceBuilder {
    /// <p>The trace action details used with the Guardrail.</p>
    pub fn action(mut self, input: crate::types::GuardrailAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The trace action details used with the Guardrail.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::GuardrailAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>The trace action details used with the Guardrail.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::GuardrailAction> {
        &self.action
    }
    /// <p>The details of the trace Id used in the Guardrail Trace.</p>
    pub fn trace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details of the trace Id used in the Guardrail Trace.</p>
    pub fn set_trace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trace_id = input;
        self
    }
    /// <p>The details of the trace Id used in the Guardrail Trace.</p>
    pub fn get_trace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.trace_id
    }
    /// Appends an item to `input_assessments`.
    ///
    /// To override the contents of this collection use [`set_input_assessments`](Self::set_input_assessments).
    ///
    /// <p>The details of the input assessments used in the Guardrail Trace.</p>
    pub fn input_assessments(mut self, input: crate::types::GuardrailAssessment) -> Self {
        let mut v = self.input_assessments.unwrap_or_default();
        v.push(input);
        self.input_assessments = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details of the input assessments used in the Guardrail Trace.</p>
    pub fn set_input_assessments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>) -> Self {
        self.input_assessments = input;
        self
    }
    /// <p>The details of the input assessments used in the Guardrail Trace.</p>
    pub fn get_input_assessments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>> {
        &self.input_assessments
    }
    /// Appends an item to `output_assessments`.
    ///
    /// To override the contents of this collection use [`set_output_assessments`](Self::set_output_assessments).
    ///
    /// <p>The details of the output assessments used in the Guardrail Trace.</p>
    pub fn output_assessments(mut self, input: crate::types::GuardrailAssessment) -> Self {
        let mut v = self.output_assessments.unwrap_or_default();
        v.push(input);
        self.output_assessments = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details of the output assessments used in the Guardrail Trace.</p>
    pub fn set_output_assessments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>>) -> Self {
        self.output_assessments = input;
        self
    }
    /// <p>The details of the output assessments used in the Guardrail Trace.</p>
    pub fn get_output_assessments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailAssessment>> {
        &self.output_assessments
    }
    /// <p>Contains information about the Guardrail output.</p>
    pub fn metadata(mut self, input: crate::types::Metadata) -> Self {
        self.metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the Guardrail output.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<crate::types::Metadata>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>Contains information about the Guardrail output.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<crate::types::Metadata> {
        &self.metadata
    }
    /// Consumes the builder and constructs a [`GuardrailTrace`](crate::types::GuardrailTrace).
    pub fn build(self) -> crate::types::GuardrailTrace {
        crate::types::GuardrailTrace {
            action: self.action,
            trace_id: self.trace_id,
            input_assessments: self.input_assessments,
            output_assessments: self.output_assessments,
            metadata: self.metadata,
        }
    }
}
impl ::std::fmt::Debug for GuardrailTraceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GuardrailTraceBuilder");
        formatter.field("action", &"*** Sensitive Data Redacted ***");
        formatter.field("trace_id", &"*** Sensitive Data Redacted ***");
        formatter.field("input_assessments", &"*** Sensitive Data Redacted ***");
        formatter.field("output_assessments", &"*** Sensitive Data Redacted ***");
        formatter.field("metadata", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
