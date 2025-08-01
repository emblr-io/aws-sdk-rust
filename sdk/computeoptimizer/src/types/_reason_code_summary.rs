// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of a finding reason code.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReasonCodeSummary {
    /// <p>The name of the finding reason code.</p>
    pub name: ::std::option::Option<crate::types::FindingReasonCode>,
    /// <p>The value of the finding reason code summary.</p>
    pub value: f64,
}
impl ReasonCodeSummary {
    /// <p>The name of the finding reason code.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::FindingReasonCode> {
        self.name.as_ref()
    }
    /// <p>The value of the finding reason code summary.</p>
    pub fn value(&self) -> f64 {
        self.value
    }
}
impl ReasonCodeSummary {
    /// Creates a new builder-style object to manufacture [`ReasonCodeSummary`](crate::types::ReasonCodeSummary).
    pub fn builder() -> crate::types::builders::ReasonCodeSummaryBuilder {
        crate::types::builders::ReasonCodeSummaryBuilder::default()
    }
}

/// A builder for [`ReasonCodeSummary`](crate::types::ReasonCodeSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReasonCodeSummaryBuilder {
    pub(crate) name: ::std::option::Option<crate::types::FindingReasonCode>,
    pub(crate) value: ::std::option::Option<f64>,
}
impl ReasonCodeSummaryBuilder {
    /// <p>The name of the finding reason code.</p>
    pub fn name(mut self, input: crate::types::FindingReasonCode) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the finding reason code.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::FindingReasonCode>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the finding reason code.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::FindingReasonCode> {
        &self.name
    }
    /// <p>The value of the finding reason code summary.</p>
    pub fn value(mut self, input: f64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the finding reason code summary.</p>
    pub fn set_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the finding reason code summary.</p>
    pub fn get_value(&self) -> &::std::option::Option<f64> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ReasonCodeSummary`](crate::types::ReasonCodeSummary).
    pub fn build(self) -> crate::types::ReasonCodeSummary {
        crate::types::ReasonCodeSummary {
            name: self.name,
            value: self.value.unwrap_or_default(),
        }
    }
}
