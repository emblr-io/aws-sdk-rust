// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the AWS Mainframe Modernization managed application step summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct M2ManagedApplicationStepSummary {
    /// <p>The step input of the AWS Mainframe Modernization managed application step summary.</p>
    pub step_input: ::std::option::Option<crate::types::M2ManagedApplicationStepInput>,
    /// <p>The step output of the AWS Mainframe Modernization managed application step summary.</p>
    pub step_output: ::std::option::Option<crate::types::M2ManagedApplicationStepOutput>,
}
impl M2ManagedApplicationStepSummary {
    /// <p>The step input of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn step_input(&self) -> ::std::option::Option<&crate::types::M2ManagedApplicationStepInput> {
        self.step_input.as_ref()
    }
    /// <p>The step output of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn step_output(&self) -> ::std::option::Option<&crate::types::M2ManagedApplicationStepOutput> {
        self.step_output.as_ref()
    }
}
impl M2ManagedApplicationStepSummary {
    /// Creates a new builder-style object to manufacture [`M2ManagedApplicationStepSummary`](crate::types::M2ManagedApplicationStepSummary).
    pub fn builder() -> crate::types::builders::M2ManagedApplicationStepSummaryBuilder {
        crate::types::builders::M2ManagedApplicationStepSummaryBuilder::default()
    }
}

/// A builder for [`M2ManagedApplicationStepSummary`](crate::types::M2ManagedApplicationStepSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct M2ManagedApplicationStepSummaryBuilder {
    pub(crate) step_input: ::std::option::Option<crate::types::M2ManagedApplicationStepInput>,
    pub(crate) step_output: ::std::option::Option<crate::types::M2ManagedApplicationStepOutput>,
}
impl M2ManagedApplicationStepSummaryBuilder {
    /// <p>The step input of the AWS Mainframe Modernization managed application step summary.</p>
    /// This field is required.
    pub fn step_input(mut self, input: crate::types::M2ManagedApplicationStepInput) -> Self {
        self.step_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>The step input of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn set_step_input(mut self, input: ::std::option::Option<crate::types::M2ManagedApplicationStepInput>) -> Self {
        self.step_input = input;
        self
    }
    /// <p>The step input of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn get_step_input(&self) -> &::std::option::Option<crate::types::M2ManagedApplicationStepInput> {
        &self.step_input
    }
    /// <p>The step output of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn step_output(mut self, input: crate::types::M2ManagedApplicationStepOutput) -> Self {
        self.step_output = ::std::option::Option::Some(input);
        self
    }
    /// <p>The step output of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn set_step_output(mut self, input: ::std::option::Option<crate::types::M2ManagedApplicationStepOutput>) -> Self {
        self.step_output = input;
        self
    }
    /// <p>The step output of the AWS Mainframe Modernization managed application step summary.</p>
    pub fn get_step_output(&self) -> &::std::option::Option<crate::types::M2ManagedApplicationStepOutput> {
        &self.step_output
    }
    /// Consumes the builder and constructs a [`M2ManagedApplicationStepSummary`](crate::types::M2ManagedApplicationStepSummary).
    pub fn build(self) -> crate::types::M2ManagedApplicationStepSummary {
        crate::types::M2ManagedApplicationStepSummary {
            step_input: self.step_input,
            step_output: self.step_output,
        }
    }
}
