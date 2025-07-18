// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a TN3270 summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Tn3270Summary {
    /// <p>The step input of the TN3270 summary.</p>
    pub step_input: ::std::option::Option<crate::types::Tn3270StepInput>,
    /// <p>The step output of the TN3270 summary.</p>
    pub step_output: ::std::option::Option<crate::types::Tn3270StepOutput>,
}
impl Tn3270Summary {
    /// <p>The step input of the TN3270 summary.</p>
    pub fn step_input(&self) -> ::std::option::Option<&crate::types::Tn3270StepInput> {
        self.step_input.as_ref()
    }
    /// <p>The step output of the TN3270 summary.</p>
    pub fn step_output(&self) -> ::std::option::Option<&crate::types::Tn3270StepOutput> {
        self.step_output.as_ref()
    }
}
impl Tn3270Summary {
    /// Creates a new builder-style object to manufacture [`Tn3270Summary`](crate::types::Tn3270Summary).
    pub fn builder() -> crate::types::builders::Tn3270SummaryBuilder {
        crate::types::builders::Tn3270SummaryBuilder::default()
    }
}

/// A builder for [`Tn3270Summary`](crate::types::Tn3270Summary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Tn3270SummaryBuilder {
    pub(crate) step_input: ::std::option::Option<crate::types::Tn3270StepInput>,
    pub(crate) step_output: ::std::option::Option<crate::types::Tn3270StepOutput>,
}
impl Tn3270SummaryBuilder {
    /// <p>The step input of the TN3270 summary.</p>
    /// This field is required.
    pub fn step_input(mut self, input: crate::types::Tn3270StepInput) -> Self {
        self.step_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>The step input of the TN3270 summary.</p>
    pub fn set_step_input(mut self, input: ::std::option::Option<crate::types::Tn3270StepInput>) -> Self {
        self.step_input = input;
        self
    }
    /// <p>The step input of the TN3270 summary.</p>
    pub fn get_step_input(&self) -> &::std::option::Option<crate::types::Tn3270StepInput> {
        &self.step_input
    }
    /// <p>The step output of the TN3270 summary.</p>
    pub fn step_output(mut self, input: crate::types::Tn3270StepOutput) -> Self {
        self.step_output = ::std::option::Option::Some(input);
        self
    }
    /// <p>The step output of the TN3270 summary.</p>
    pub fn set_step_output(mut self, input: ::std::option::Option<crate::types::Tn3270StepOutput>) -> Self {
        self.step_output = input;
        self
    }
    /// <p>The step output of the TN3270 summary.</p>
    pub fn get_step_output(&self) -> &::std::option::Option<crate::types::Tn3270StepOutput> {
        &self.step_output
    }
    /// Consumes the builder and constructs a [`Tn3270Summary`](crate::types::Tn3270Summary).
    pub fn build(self) -> crate::types::Tn3270Summary {
        crate::types::Tn3270Summary {
            step_input: self.step_input,
            step_output: self.step_output,
        }
    }
}
